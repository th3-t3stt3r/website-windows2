# Module imports
import os
import pathlib
import re
import logging
from threading import Thread
import time
import psutil

# File Imports
from app.logger import logger
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from app.config import GeneralConfig as gc
from app.proc_killer import ProcessKiller
from app.os_setup import getUsers, windowsConfig, restorePoint


# Start Monitor
def start():
    """Function to start an instance of Monitor"""
    global fm
    fm = Monitor()
    fm.run()


class Monitor:
    """File Monitor class"""

    def __init__(self):
        self.process_whitelist = []
        self.user_whitelist = []
        self.started = False
        self.start_protection_time = time.time()
        self.update_user_whitelist_time = time.time()

 #

    def run(self):
        """Function to run the File Monitor"""
        observers = []
        observer = Observer()
        event_handler = self.EventHandler()

        # Create Watchdog Observer for the selected directories
        for directory in gc.selected_directories:
            observer.schedule(event_handler, directory, recursive=True)
            observers.append(observer)

         # Create Watchdog Observer for the honeyfolder
        if os.path.exists(gc.PATH_TO_HONEYFOLDER):
            observer.schedule(event_handler, gc.PATH_TO_HONEYFOLDER, recursive=True)
            observers.append(observer)

        observer.start()

        try:
            while True:
                if not self.started:
                    if (time.time() - self.start_protection_time) > 3:
                        self.getProcesses()
                        self.user_whitelist = getUsers()
                        windowsConfig(self.user_whitelist, 'check')
                        restorePoint()
                        windowsConfig(self.user_whitelist, 'set')

                        self.started = True
                        logger.debug('BunnyShield Monitor has started.')
                        logger.debug(f'Currently monitoring {len(observers)} directories.')

                if (time.time() - self.update_user_whitelist_time) > 300:
                    old_user_whitelist = self.user_whitelist
                    self.user_whitelist = getUsers()
                    self.update_user_whitelist_time = time.time()

                    for user in self.user_whitelist:
                        if user not in old_user_whitelist:
                            logger.debug(f'Updated user list')
                            break

                continue

        except KeyboardInterrupt or SystemExit:
            logger.debug("Stopping BunnyShield Monitor.")
            for observer in observers:
                observer.unschedule_all()
                observer.stop()
                observer.join()

    #

    def getProcesses(self):
        """Function to get the process Whitelist"""
        threads = []

        for process in psutil.process_iter():
            th = Thread(target=self.getProcessDict, args=[process])
            th.start()
            threads.append(th)

        for th in threads:
            th.join()
    #

    def getProcessDict(self, process):
        try:
            process_dict = {
                "pid": process.pid,
                "name": process.name(),
                "create_time": process.create_time()
            }
            self.process_whitelist.append(process_dict)

        except Exception as e:
            # logger.error(e)
            pass

    #

    class EventHandler(FileSystemEventHandler):
        """Watchdog Event Handler Class"""

        def __init__(self):
            # Events count
            self.unknow_extension_event_count = 0
            self.honey_folder_edit_event_count = 0
            self.created_event_count = 0
            self.moved_event_count = 0
            self.modified_event_count = 0
            self.deleted_event_count = 0

            # Events current time
            self.honey_folder_change_current_time = time.time()
            self.created_current_time = time.time()
            self.moved_current_time = time.time
            self.modified_current_time = time.time()
            self.deleted_current_time = time.time()
            self.check_ransom_current_time = time.time()

            # Misc
            self.check_ransom = False

        #

        def on_created(self, event):
            """Function to monitor created file events in the provided directories and the honeyfolder"""
            if self.isAppDataOrTemp(event.src_path):
                # print(event.src_path)
                self.created_event_count += 1

                self.checkForHoneyfolderEdit(event.src_path, 'created')
                self.checkForUnknowExt(event.src_path, 'created')
                self.checkCount('created')

                if self.check_ransom:
                    self.checkForRansomware()

        #

        def on_moved(self, event):
            if self.isAppDataOrTemp(event.src_path):
                #  print(event.src_path)
                self.moved_event_count += 1

                self.checkForHoneyfolderEdit(event.src_path, 'moved')
                self.checkForUnknowExt(event.src_path, 'moved')
                self.checkCount('moved')

                if self.check_ransom:
                    self.checkForRansomware()

        #

        def on_modified(self, event):
            """Function to monitor modified file events in the provided directories and the honeyfolder"""
            if self.isAppDataOrTemp(event.src_path):
                # print(event.src_path)
                self.modified_event_count += 1

                self.checkForHoneyfolderEdit(event.src_path, 'modified')
                self.checkCount('modified')

                # Check for Ransomware
                if self.check_ransom:
                    self.checkForRansomware()

        #

        def on_deleted(self, event):
            """Function to monitor deleted file events in the provided directories and the honeyfolder"""
            if self.isAppDataOrTemp(event.src_path):
                # print(event.src_path)
                self.deleted_event_count += 1

                # Check if the honeyfolder was affected
                self.checkForHoneyfolderEdit(event.src_path, 'deleted')
                self.checkCount('deleted')

                # Check for Ransomware
                if self.check_ransom:
                    self.checkForRansomware()

        #

        def isAppDataOrTemp(self, event_path):
            if gc.PATH_TO_APPDATA in event_path or gc.PATH_TO_TEMP in event_path or gc.PATH_TO_MAIN_FOLDER in event_path:
                return False
            else:
                return True

        #

        def checkForUnknowExt(self, event_path, event_action):
            if not os.path.isdir(event_path):
                try:
                    has_know_ext = False
                    file_ext = pathlib.Path(re.findall(gc.LAST_FILE_PATTERN, event_path)[0]).suffix

                    if file_ext in gc.FILE_EXT_LIST:
                        has_know_ext = True

                    if not has_know_ext and not file_ext == "":
                        if event_action == 'created':
                            new_time = time.time() - self.created_current_time
                        elif event_action == 'moved':
                            new_time = time.time() - self.moved_current_time

                        self.unknow_extension_event_count += 1

                        if new_time > 1:
                            logger.warning(f"Unknow file extension detected \"{file_ext}\"{'' if self.unknow_extension_event_count <= 1 else ' (and ' + str(self.unknow_extension_event_count) + ' more)'}.")

                            if self.unknow_extension_event_count > gc.unknow_extension_event_count_trigger:
                                self.unknow_extension_event_count = 0
                                self.check_ransom = True

                            if event_action == 'created':
                                self.created_current_time = time.time()
                            if event_action == 'moved':
                                self.moved_current_time = time.time()

                except Exception as e:
                    # logger.error(e)
                    pass

        #

        def checkForHoneyfolderEdit(self, event_path, event_action):
            if gc.PATH_TO_HONEYFOLDER in event_path and not self.check_ransom:
                new_time = time.time() - self.honey_folder_change_current_time
                self.honey_folder_edit_event_count += 1

                if new_time > 1:
                    logger.warning(f"File {event_action} in Honeyfolder{'' if self.honey_folder_edit_event_count <= 1 else ' (and ' + str(self.honey_folder_edit_event_count) + ' more)'}.")
                    self.honey_folder_change_current_time = time.time()
                    self.honey_folder_edit_event_count = 0
                    self.check_ransom = True

        #

        def checkCount(self, event_action):

            try:
                event_count, current_time = self.returnEventData(event_action, 'get')

                if event_count >= gc.event_count_trigger and not self.check_ransom:
                    new_time = time.time() - current_time

                    if new_time > 10:
                        logger.warning(f"Various files {event_action} ({event_count} files).")
                        self.returnEventData(event_action, 'reset')
                        self.check_ransom = True
                    else:
                        self.returnEventData(event_action, 'reset')
            except:
                pass
        #

        def returnEventData(self, event_action, action):
            if event_action == 'created':
                if action == 'get':
                    return self.created_event_count, self.created_current_time
                if action == 'reset':
                    self.created_event_count = 0
                    self.created_current_time = time.time()

            if event_action == 'moved':
                if action == 'get':
                    return self.moved_event_count, self.moved_current_time
                if action == 'reset':
                    self.moved_event_count = 0
                    self.moved_current_time = time.time()

            if event_action == 'modified':
                if action == 'get':
                    return self.modified_event_count, self.modified_current_time
                if action == 'reset':
                    self.modified_event_count = 0
                    self.modified_current_time = time.time()

            if event_action == 'deleted':
                if action == 'get':
                    return self.deleted_event_count, self.deleted_current_time
                if action == 'reset':
                    self.deleted_event_count = 0
                    self.deleted_current_time = time.time()

        #

        def checkForRansomware(self):
            new_time = time.time() - self.check_ransom_current_time
            if new_time > gc.check_ransom_time:
                self.check_ransom_current_time = time.time()
                ProcessKiller().findRansomwareProcess(fm.process_whitelist, fm.user_whitelist)
                self.check_ransom = False


# MAIN
if __name__ == "__main__":
    pass
else:
    from app.logger import logger
    logging.getLogger("watchdog.observers.inotify_buffer").disabled = True
