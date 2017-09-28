#!/usr/bin/env python2


"""
Module to believeably detect binary patching.
"""


# ===== IMPORTS =====

import logging
import subprocess;
import os.path;
from os import rename,remove,system;
from sys import exit;
from multiprocessing import Lock;
from time import sleep;
from random import choice,randint,getrandbits;
from hashlib import sha256;
from socket import timeout;
import signal;
import psutil;

from util import exiturl

import BeautifulSoup;
import requests;

from marionette_driver.marionette import Marionette;
from marionette_driver.marionette import HTMLElement;
from marionette_driver.marionette import Actions;
from marionette_driver import errors;
from marionette_driver.errors import InvalidSessionIdException;
from marionette_driver.errors import MarionetteException;
from marionette_driver.errors import UnknownException;
from marionette_driver import By;


# ===== GLOBALS =====

# exitmap global log
log = logging.getLogger(__name__)

# tor browser mutex
mutex = None;

# destinations array (required by module interface)
destinations = [("filehippo.com", 80),("cnet.com", 80)];

# tell eventhandler this module needs autoattaching
autoattach = True;

# word blacklist for downloads that don't lead to a binary
blacklist_dls = [
    'microsoft',
    'google'
];

# pseudo-enum for status
class Status:
    IDENTICAL=1;
    NONIDENT=2;
    NODL=3;
    CRIT=4;


# ===== SETTINGS =====

# where is the tor browser located (containing directory)
tb_dir = os.path.expanduser('~/.local/share/torbrowser/tbb/x86_64/tor-browser_en-US');
# launcher binary relative to tb_dir
tb_launcher = 'Browser/start-tor-browser';
# the user.js file of the firefox web browser allows to inject settings
userjs_dir = 'Browser/TorBrowser/Data/Browser/profile.default';
userjs_fn = 'user.js';
# automatically store downloaded files here
dl_dir = 'Browser/Downloads/';
dl_dir_abs = None;

# folder relative to current working directory
# (not relative to tb_dir)
# where altered binaries should be stored for later analyzation
bad_dir = 'baddls/';
assert os.path.isdir(bad_dir);

# stores a list of fingerprints that...
# ...were successfully checked (unmodified binary)
success_fp_file='success.txt';
# ...were malicious (modified binary)
malicious_fp_file='malicious.txt';
# ...failed
fail_fp_file='failed-fps.txt';
# ...ran into timeout somewhere
timeouted_fp='timeout-fps.txt';
# you can run the check again easily
# with only the timeouted exits from that list

# wait for dl to start until simulating click on
# "if the download didn't start automatically"
seconds_until_manual_dl = 30;
# wait for dl to start after that, or if no such
# manual start link is available
seconds_wait_for_dl_start = 300;
# wait for dl to finish
seconds_timeout_for_dl = 900;
# interval at which polling for dl status change happens
seconds_check_for_fs_change = 10;



# ===== UTIL =====

# configure tor browser to use exitmap's circuits instead
# of using its own.
# @param socks_port socks port opened by exitmap.
def set_port(socks_port):
    # check for directories
    global tb_dir;
    log.debug("torbrowser setup with socks port %d." % socks_port);
    userjs_fulldir = os.path.join(tb_dir, userjs_dir);
    userjs_path = os.path.join(userjs_fulldir, userjs_fn);
    if ( not os.path.isdir(tb_dir) ) or ( not os.path.isdir(userjs_fulldir) ):
        exit('Tor browser profile directory not found: %s, change variables tb_dir and userjs_dir and try again.' % tb_dir);
    
    # backup existing userjs file
    if os.path.isfile(userjs_path):
        userjs_orig_path = userjs_path+'.orig';
        if not os.path.isfile(userjs_orig_path):
            rename(userjs_path,userjs_orig_path);
    
    userjs_file = open(userjs_path,'w');
    # add port
    userjs_file.write('user_pref("network.proxy.socks_port",'+str(socks_port)+');');
    # set proxy type to socks
    userjs_file.write('user_pref("network.proxy.type",1);');
    # prevent torbrowser from launching its own tor instance
    userjs_file.write('user_pref("extensions.torlauncher.start_tor",false);');
    # download unknown file types (binaries) without asking
    userjs_file.write('user_pref("browser.helperApps.neverAsk.saveToDisk","application/octet-stream");');
    userjs_file.close();

# restore original userjs file
def cleanup_userjs():
    # check for directories
    log.debug("torbrowser cleanup.");
    userjs_fulldir = os.path.join(tb_dir, userjs_dir);
    userjs_path = os.path.join(userjs_fulldir, userjs_fn);
    if ( not os.path.isdir(tb_dir) ) or ( not os.path.isdir(userjs_fulldir) ):
        exit('Tor browser profile directory not found: %s, change variables tb_dir and userjs_dir and try again.' % tb_dir);
    # remove injected userjs
    if os.path.isfile(userjs_path):
        remove(userjs_path);
    # restore original userjs
    userjs_orig_path = userjs_path+'.orig'
    if os.path.isfile(userjs_orig_path):
        rename(userjs_orig_path,userjs_path);

# returns list of all files in the @tt wdir directory that
# are not in the passed list @tt file_list_before_dl already.
# due to how this is called, it filters out .part files and
# checks whether there is only one new file - otherwise something
# else is creating files, which is unwanted.
def get_new_files(wdir, file_list_before_dl):
    file_list = os.listdir(wdir);
    log.info("files after dl: %s" % str(file_list));
    new_files = [ x for x in file_list if not x in file_list_before_dl and not x.endswith('.part')];
    if len(new_files) == 1:
        return new_files;
    else:
        if len(new_files) != 0:
            log.error("dl dir behaved strange (mutex fail?), list of new files: %s" % str(new_files));
            exit(1);
    return [];

# periodically poll dl dir to find the newly downloaded file
# then poll for whether the .part file still exists, if it's gone,
# the download has finished.
def wait_for_dl_to_finish(wdir, file_list_before_dl, url, client=None):
    global seconds_until_manual_dl, seconds_wait_for_dl_start, seconds_check_for_fs_change;
    assert(wdir is not None);
    # wait for checking dl status
    sleep(seconds_until_manual_dl);
    new_files = get_new_files(wdir, file_list_before_dl)
    # check whether a dl has started
    if len(new_files) == 0:
        # if not, click manual retry link
        manual_retry(client);
        # then wait again (periodic poll until timeout)
        for s in range(0, seconds_wait_for_dl_start/seconds_check_for_fs_change):
            sleep(seconds_check_for_fs_change);
            new_files = get_new_files(wdir, file_list_before_dl);
            if len(new_files) > 0:
                break;
        # if still no download, stop trying
        if len(new_files) == 0:
            log.error("no file downloaded from %s" % str(url));
            return None;
        
    # 2nd part: wait for dl to finish
    # (repeatedly poll for .part file)
    fn = os.path.join(wdir, new_files[0]);
    fnp = fn+'.part'
    assert(os.path.isfile(fn));
    finished = False;
    for s in range(0, seconds_timeout_for_dl/seconds_check_for_fs_change):
        sleep(seconds_check_for_fs_change);
        if not os.path.isfile(fnp):
            finished = True;
            break;
    if not finished:
        log.error("dl did not finish after %d seconds: %s" % (seconds_timeout_for_dl,str(fn)));
        return None;
    return fn;

# returns a string with the hex representation
# of the sha256 checksum of the file @tt fn
def sha256sum(fn):
    chunk_size = 1048576 # 1024 B * 1024 B = 1048576 B = 1 MB
    file_sha256_checksum = sha256();
    with open(fn, "rb") as f:
        byte = f.read(chunk_size)
        while byte:
            file_sha256_checksum.update(byte)
            byte = f.read(chunk_size)
    return file_sha256_checksum.hexdigest();

# check whether a list contains another list
# (ordered, not just its elements)
def contains(small, big):
    for i in xrange(1 + len(big) - len(small)):
        if small == big[i:i+len(small)]:
            return True;
    return False;

# quit a torbrowser instance without running into a situation
# that requires manual interaction
def cancel_all_downloads_and_exit(client,tb_proc):
    # marionette connection might already be broken at this point => try
    try:
        # if downloads aren't cancelled, the browser shows a yes/no-dialogue
        # whether to really exit, which prevents shutdown and can't be resolved
        # programmatically, and the setting to override that dialogue has been
        # removed.
        
        # set context to Chrome to have the Downloads interface available.
        client.set_context(client.CONTEXT_CHROME);
        
        # this is the only way marionette supports cancelling downloads.
        # it executes javascript in the browser's chrome context
        # which interfaces to the internal Downloads module of firefox.
        
        # it loops over all downloads and cancels every one of them.
        # the import imports the Donwloads chrome interface
        # Task.spawn() is required because the code includes so-called
        #  "generator functions", Promises and yields, which would need
        #  to be stepped over if not used with Task.spawn().
        # getList() returns a Promise of type DownloadList, which needs
        #  to be converted to a normal Array for looping over with getAll().
        # for-of-loops are the javascript variant of for-in over array elements.
        #  there is for-in in javascript but it loops over all object
        #  properties, eg. for an Array the .length attribute would be one
        #  of the iteration elements as well.
        # finalize() force-cancels regardless of state and prevents other
        #  callers from interfering with the operation. The argument tells
        #  finalize() to discard and remove partially downloaded data.
        script_rv = client.execute_async_script('''
            Components.utils.import("resource://gre/modules/Downloads.jsm");
            
            Task.spawn(function () {
                var dlist = yield Downloads.getList(Downloads.ALL);
                var darray = yield dlist.getAll();
                for(i of darray){
                    yield i.finalize(true);
                }
                marionetteScriptFinished(1);
            });
            ''');
        
        # reset context to Content
        client.set_context(client.CONTEXT_CONTENT);
        log.debug('cancelled dls');
        # replication of quit(in_app=True) behaviour
        client._request_in_app_shutdown()
        # Ensure to explicitely mark the session as deleted
        client.delete_session(send_request=False, reset_session_id=True)
        # Give the application some time to shutdown
        if client.instance: client.instance.runner.wait(timeout=self.DEFAULT_SHUTDOWN_TIMEOUT)
    except InvalidSessionIdException:
        # just continue if marionette client session is gone
        pass;
    log.debug('waiting for torbrowser to exit');
    # wait() does not work because firefox forks itself away from the launcher
    #tb_proc.wait();
    # there is no way to reliably detect whether a graceful shutdown of firefox
    # has been successfully completed => sleep()
    sleep(5);
    
    # part 2: the above "graceful termination request" unfortunately does not guarantee
    # firefox has closed and there is no mechanism to check. So instead we just kill
    # all still-living tor browser firefox instances.
    cprocs = [];
    tbprocs = [];
    # get all processes from all trees, not only the parent processes
    # this is necessary because the torbrowser firefox instance is a child of the launcher
    for p in psutil.process_iter():
        try:
            cprocs.extend(p.children(recursive=True));
        except psutil.NoSuchProcess:
            pass;
    # cannot do this with list comprehension because needs try-catch per element.
    for p in cprocs:
        try:
            if 'firefox' in p.name() and contains(['--class', 'Tor Browser'], p.cmdline()):
                tbprocs.append(p);
        except psutil.NoSuchProcess:
            pass;
    # iterate over all firefox processes which are tor browser instances (started with --class "Tor Browser")
    for p in tbprocs:
        try:
            # ...and kill them.
            p.kill();
        except psutil.NoSuchProcess:
            # just continue if the process has already exited (might happen for firefox's child processes)
            pass;
    log.debug('finished waiting.');



# ===== MODULE =====

# setup: create mutex (only one tor browser at a time),
#  check for directories' existence,
#  touch files
def setup():
    global mutex, tb_dir, dl_dir, dl_dir_abs, success_fp_file, malicious_fp_file, fail_fp_file, timeouted_fp;
    mutex = Lock();
    dl_dir_abs = os.path.join(tb_dir, dl_dir);
    if not os.path.isdir(dl_dir_abs):
        log.error('Tor browser download directory not found: %s, change variable dl_dir (or tb_dir) and try again.' % dl_dir_abs);
        exit();
    # create files if not existing
    if not os.path.isfile(success_fp_file):
        open(success_fp_file, 'a').close();
    if not os.path.isfile(malicious_fp_file):
        open(malicious_fp_file, 'a').close();
    if not os.path.isfile(fail_fp_file):
        open(fail_fp_file, 'a').close();
    if not os.path.isfile(timeouted_fp):
        open(timeouted_fp, 'a').close();

# setup for every exit:
#  set port to tor browser,
#  start browser,
#  start marionette and connect it to browser
#  set marionette socket timeout
def single_setup(socks_port,run_cmd_over_tor):
    global tb_dir, tb_launcher, userjs_dir;
    client = None;
    tb_proc = None;
    set_port(socks_port);
    # launch tor browser
    tb_launcher_fullpath = os.path.join(tb_dir, tb_launcher);
    userjs_fulldir = os.path.join(tb_dir, userjs_dir);
    if not os.path.isfile(tb_launcher_fullpath):
        exit('Tor browser launcher not found: %s, change variables tb_dir and tb_launcher and try again.' % tb_launcher_fullpath);
    if ( not os.path.isdir(tb_dir) ) or ( not os.path.isdir(userjs_fulldir) ):
        exit('Tor browser profile directory not found: %s, change variables tb_dir and userjs_dir and try again.' % tb_dir);
    # launch with marionette support and custom starup url
    # (when using your own tor instance the default startpage reports a problem)
    tb_proc = subprocess.Popen([tb_launcher_fullpath, '--class', 'Tor Browser', '-profile', userjs_fulldir, '-marionette', '-url', 'about:blank', '-foreground']);
    # wait until browser has started listening on marionette port
    sleep(2);
    # connect to marionette
    client = Marionette('localhost', port=2828, socket_timeout=360);
    client.start_session();
    log.debug("tor browser started.");
    log.debug('default pageload timeout: %s' % str(client.timeout.page_load));
    # in ms. default 60s.
    client.set_page_load_timeout(360000);
    client.timeout.page_load = 360;
    log.debug('set timeout to: %s' % str(client.timeout.page_load));
    log.debug("marionette created.");
    return client, tb_proc;

# no teardown action
def teardown():
    pass;

# after checked node, restore original userjs
def teardown_single():
    cleanup_userjs();

# main probing routine.
def probe(exit_desc, run_python_over_tor, run_cmd_over_tor, **kwargs):
    global mutex, success_fp_file, malicious_fp_file, fail_fp_file, timeouted_fp;
    client = None;
    tb_proc = None;
    socks_port = 0;
    fn = None;
    
    # check whether setup was done correctly and caller is patched
    if 'socks_port' in kwargs:
        socks_port = kwargs['socks_port'];
    else:
        log.error("no socks port passed.");
        return;
    if mutex is None:
        exit("Mutex doesn't exist");

    # get tb mutex before starting tor browser
    mutex.acquire();
    log.debug("mutex %s acquired." % str(mutex));

    # module setup
    client, tb_proc = single_setup(socks_port, run_cmd_over_tor);
    if client is None:
        exit('Error: marionette session connection not found');

    # variable setup
    exit_url = exiturl(exit_desc.fingerprint)
    elementExists = True;
    fp = str(exit_desc.fingerprint);
    works = True;
    
    log.info('start checking exit %s' % fp);

    # do the site-specific probing
    use_cnet = bool(getrandbits(1));
    try:
        if use_cnet:
            status, fn = cnet(client);
        else:
            status, fn = filehippo(client);
    except InvalidSessionIdException:
        works = False;
    except UnknownException as uex:
        if not 'Reached error page' in str(uex):
            raise;
        else:
            works = False;
    # if there was some problem with one of the sites,
    # just try the other one
    if not works:
        log.warn(':::::::::: session gone or timeout, 1st try');
        works = True;
        try:
            if use_cnet:
                status, fn = filehippo(client);
            else:
                status, fn = cnet(client);
        except InvalidSessionIdException:
            works = False;
        except UnknownException as uex:
            if not 'Reached error page' in str(uex):
                raise;
            else:
                works = False;
        if not works:
            log.warn(':::::::::: session gone or timeout, 2nd try');
            log.warn('giving up.');
            # log exitnode to timeout file
            with open(timeouted_fp,'a') as f:
                f.write('%s\n'%fp)
            sleep(10);
            cancel_all_downloads_and_exit(client,tb_proc);
            client = None;
            tb_proc = None;
            teardown_single();
            return mutex;

    # check return status and log fingerprint to corresponding file.
    
    if status == Status.NONIDENT:
        log.error("!!! HASH MISMATCH: original file hash %s" % sha256sum('test.exe'));
        with open(malicious_fp_file,'a') as f:
            f.write('%s\n'%fp)
        # we found a binary patched file!
        # move to safe location
        rename(fn, os.path.join(bad_dir,os.path.basename(fn)+'.'+fp));
    elif status == Status.IDENTICAL:
        log.info("+++ HASH CORRECT: original file hash %s" % sha256sum('test.exe'));
        with open(success_fp_file,'a') as f:
            f.write('%s\n'%fp)
        # clean up
        remove(fn);
    elif status == Status.NODL:
        log.warn("@@@@@@@@@@ no file downloaded");
        with open(fail_fp_file,'a') as f:
            f.write('%s\n'%fp)
    elif status == Status.CRIT:
        log.warn("critical error, exiting.");
        cancel_all_downloads_and_exit(client, tb_proc);
        teardown_single();
        exit(1);
    
    # stop down tor browser and return
    log.info("Exit %s done." % fp);
    cancel_all_downloads_and_exit(client, tb_proc);
    client = None;
    tb_proc = None;
    teardown_single();
    return mutex;



# ===== site-specific functions =====

# click on the "download didn't start automatically" link
def manual_retry(client):
    try:
        manual_dl_link = client.find_element(By.ID, 'pdl-manual');
        manual_dl_link.click();
    except: pass;


# the filehippo and cnet functions are highly specific
# to the website and will most likely break and need adjustment
# frequently. Both navigate to the front page, select a download
# from the "top 10" list, and navigate through the intermediate
# page(s) until the dl starts, then re-dl the same file over
# clearnet. finally both files are hashed, hashes compared and
# corresponding status returned.


# check filehippo
def filehippo(client):
    global dl_dir_abs;
    url = 'http://filehippo.com';
    elementExists = True;
    try:
        client.navigate(url);
    except timeout as texp:
        log.info("ignoring timeout: %s" % str(texp));
        pass;
    element = client.find_element(By.ID, 'popular-list');
    elementList = element.find_elements(By.TAG_NAME, 'a');
    if(len(elementList) == 0):
        log.critical('no links found! filehippo() function broken?');
        return Status.CRIT, None;

    # remove blacklisted downloads
    whiteList = [i for i in elementList if not any(b in i.get_attribute('href') for b in blacklist_dls)];
    log.info("dls: %s" % str([i.get_attribute('href') for i in whiteList]));
    # select at random
    element = choice(whiteList);
    nextUrl = element.get_attribute('href');
    # random delay
    sleep(randint(1,5));
    # open next page in dl process
    try:
        client.navigate(nextUrl);
    except timeout as texp:
        log.info("ignoring timeout: %s" % str(texp));
        pass;
    # click on donwload button
    element = client.find_element(By.CSS_SELECTOR, 'a.program-header-download-link.green.button-link');
    finalUrl = None;
    try:
        finalUrl = element.get_attribute('href');
    except errors.MarionetteException:
        log.warn('error on finalUrl.');
        return Status.NODL, None;
    if finalUrl is None:
        log.warn('no finalUrl.');
        return Status.NODL, None;        
    assert(dl_dir_abs is not None);
    file_list = os.listdir(dl_dir_abs);
    log.info("files: %s" % str(file_list));
    action = Actions(client);
    action.click(element);
    action.perform();
    # wait until dl finishes
    fn = wait_for_dl_to_finish(dl_dir_abs, file_list, nextUrl);
    # hash downloaded file
    if fn is not None:
        tordl_hash = sha256sum(fn);
        log.info("file %s downloaded successfully from %s, hash: %s" % (fn,finalUrl,sha256sum(fn)));
    else:
        return Status.NODL, None;
    
    # dl same file over normal internet
    if str(finalUrl).startswith('http'):
        finalUrl = str(finalUrl);
    else:
        finalUrl = url + str(finalUrl);
    r = requests.get(finalUrl);
    soup = BeautifulSoup.BeautifulSoup(r.text);
    result = soup.find("meta",attrs={"http-equiv":"Refresh"});
    dl_url = None;
    if result:
        wait,text=result["content"].split(";");
        dl_url = text.split('=')[1].strip().lower();
        dl_url = url + dl_url;
    log.info("file url %s" % dl_url);
    r = requests.get(dl_url);
    fo = open('test.exe','wb');
    fo.write(r.content);
    fo.close();
    # hash clearnet-downloaded file
    orig_hash = sha256sum('test.exe');
    if orig_hash == tordl_hash:
        return Status.IDENTICAL, fn;
    else:
        return Status.NONIDENT, fn;

def cnet(client):
    global dl_dir_abs;
    url = 'http://download.cnet.com/';
    elementExists = True;
    try:
        client.navigate(url);
    except timeout as texp:
        log.info("ignoring timeout: %s" % str(texp));
        pass;
    element = client.find_element(By.ID, 'pop');
    elementList = element.find_elements(By.TAG_NAME, 'a');
    if(len(elementList) == 0): 
        log.critical('no links found! cnet() function broken?');
        return Status.CRIT, None;

    # remove blacklisted downloads
    # added self-link ("most-popular") to blacklist
    whiteList = [i for i in elementList if not any(b in i.get_attribute('href') for b in blacklist_dls)];
    log.info("dls: %s" % str([i.get_attribute('href') for i in whiteList]));
    # select at random
    element = choice(whiteList);
    nextUrl = element.get_attribute('href');
    # random delay
    sleep(randint(1,5));
    # open next page in dl process
    if nextUrl.startswith('/'): nextUrl = url + nextUrl;
    try:
        client.navigate(nextUrl);
    except timeout as texp:
        log.info("ignoring timeout: %s" % str(texp));
        pass;

    # random delay
    sleep(randint(1,5));
    # click on donwload button
    element = client.find_element(By.CSS_SELECTOR, 'a.dln-a');
    finalUrl = None;
    try:
        finalUrl = element.get_attribute('data-href');
    except errors.MarionetteException:
        log.warn('error on finalUrl.');
        return Status.NODL, None;
    if finalUrl is None:
        log.warn('no finalUrl.');
        return Status.NODL, None;        
    action = Actions(client);
    action.click(element);
    assert(dl_dir_abs is not None);
    file_list = os.listdir(dl_dir_abs);
    log.info("files: %s" % str(file_list));
    action.perform();
    # wait until dl finishes
    fn = wait_for_dl_to_finish(dl_dir_abs, file_list, nextUrl, client);
    # hash downloaded file
    log.info('-----------------------');
    if fn is not None:
        tordl_hash = sha256sum(fn);
        log.info("file %s downloaded successfully from %s, hash: %s" % (fn,finalUrl,sha256sum(fn)));
    else:
        return Status.NODL, None;

    # dl same file over normal internet
    r = requests.get(finalUrl);
    soup  = BeautifulSoup.BeautifulSoup(r.text);
    result=soup.find("meta",attrs={"http-equiv":"refresh"})
    dl_url = None;
    if result:
        wait,text=result["content"].split(";");
        sleep(int(wait));
        dl_url = '='.join(text.split('=')[1:]).strip();
        if dl_url.startswith('/'): dl_url = url + dl_url;
    else:
        dl_url = finalUrl;
    log.info("file url %s" % dl_url);
    r = requests.get(dl_url);
    fo = open('test.exe','wb');
    fo.write(r.content);
    fo.close();
    # hash clearnet-downloaded file
    orig_hash = sha256sum('test.exe');
    if orig_hash == tordl_hash:
        return Status.IDENTICAL, fn;
    else:
        return Status.NONIDENT, fn;


if __name__ == "__main__":
    exit("Module can only be run over Tor, and not stand-alone.")
