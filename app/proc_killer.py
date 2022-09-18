import os
import re
import time
import psutil
import subprocess
from threading import Thread
from app.os_setup import getUsers, restoreSystem
from app.config import GeneralConfig as gc


class ProcessKiller():
    """ProcessKiller Class"""

    def __init__(self):
        self.start = time.perf_counter()
        self.malicious_process_killed = False
        self.malicious_process_detected = False
        self.malicious_pid_list = []

        self.crypt_dll_list = ['crypt32.dll', 'bcrypt.dll', 'bcryptprimitives.dll', 'cryptsp.dll', 'crypt32.dll.mui', 'cryptbase.dll', 'ncryptsslp.dll', 'cryptnet.dll', 'cryptngc.dll', 'ncrypt.dll']
    #

    def getCWD(self, malicious_cwd, cmdline_list):
        malicious_file_path_pattern = "(?<=.\\\)(.*)"
        malicious_cwd_list = []

        for cmdline in cmdline_list:
            try:
                item_path = re.findall(malicious_file_path_pattern, cmdline)[0]
                final_cwd = os.path.join(malicious_cwd, item_path)

                if os.path.exists(final_cwd):
                    if malicious_cwd in final_cwd:
                        malicious_cwd_list.append(final_cwd)

            except Exception as e:
                # logger.error(e)
                pass

            try:
                if os.path.isfile(cmdline):
                    if malicious_cwd in cmdline:
                        malicious_cwd_list.append(cmdline)

            except Exception as e:
                # logger.error(e)
                pass

        return malicious_cwd_list

    #

    def findRansomwareProcess(self, process_whitelist, user_whitelist):
        """Function to check which running process might be malicious"""
        logger.warning('Scanning for Ransomware.')

        threads = []

        for process in psutil.process_iter():
            is_whitelisted = False

            for whitelisted_process in process_whitelist:
                if process.pid == whitelisted_process['pid'] and process.name() == whitelisted_process['name'] and process.create_time() == whitelisted_process['create_time']:
                    is_whitelisted = True

            if not is_whitelisted:
                try:
                    th = Thread(target=self.validateProcess, args=[process, user_whitelist])
                    th.start()
                    threads.append(th)
                except:
                    pass

        for th in threads:
            try:
                th.join()
            except:
                pass

    #

    def validateProcess(self, process, user_whitelist):
        flags = 0
        try:
            process_cwd = psutil.Process(process.pid).cwd()
            process_cmdline_list = psutil.Process(process.pid).cmdline()
            process_file_abs_path_list = self.getCWD(process_cwd, process_cmdline_list)

            # Check for process I/O
            if self.checkProcessIO(process):
                flags += 1
            else:
                return

            # Check for API/Lib calls
            if self.checkProcessCalls(process):
                flags += 1

            # Check Process AuthenticodeSignature validity
            if self.checkProcessCertificate(process_file_abs_path_list):
                flags += 1

            if flags >= 3:
                self.killProcess(process, process_file_abs_path_list, user_whitelist)

        except:
            pass

    #

    def checkProcessIO(self, process):
        """Function to check how many bytes has been written by the current process"""

        try:
            start_bytes = process.io_counters().write_bytes
            time.sleep(gc.time_to_check_io)
            final_bytes = process.io_counters().write_bytes

            if (final_bytes - start_bytes) > 100000:
                return True
            else:
                return False

        except Exception as e:
            #logger.error('ERROR AKI')
            pass

    #

    def checkProcessCalls(self, process):
        has_crypt_dll = False
        try:
            for item in process.memory_maps():
                for dll in self.crypt_dll_list:
                    if dll in item.path:
                        has_crypt_dll = True
                        break
                if has_crypt_dll:
                    break

            if has_crypt_dll:
                return True
            else:
                return False

        except Exception as e:
            #logger.error('ERROR AKI')
            pass

    #

    def checkProcessCertificate(self, process_file_abs_path_list):
        try:
            for path in process_file_abs_path_list:
                validity = subprocess.check_output(
                    ['powershell.exe', f'Get-AuthenticodeSignature -FilePath "{path}" | Select-Object -Property Status | Format-Table -hidetableheaders'],
                    shell=True).decode().strip()

                if validity.lower() != 'valid':
                    return True
                else:
                    return False

        except Exception as e:
            #logger.error('ERROR AKI')
            pass

    #

    def checkForNewUsers(self, user_whitelist):
        current_user_list = getUsers()
        new_user_list = []

        for user in current_user_list:
            if user not in user_whitelist:
                new_user_list.append(user)

        if new_user_list:
            for user in new_user_list:
                logger.critical(f"New user with name {user} detected. Deleting it.")
                subprocess.run(
                    ['powershell.exe', f'Remove-LocalUser -Name "{user}"'],
                    shell=True)

    #

    def killProcess(self, process, process_file_abs_path_list, user_whitelist):
        """Function to kill the malicious process"""
        secure_flag = 0
        try:
            psutil.Process(process.pid).status()
            logger.critical(f"Found ransomware process with PID {process.pid}. Killing it.")

            try:
                subprocess.check_output(f"taskkill /PID {process.ppid()} /F /T", shell=True, stderr=subprocess.DEVNULL)
                secure_flag += 1

            except Exception as e:
                # logger.error(e)
                pass

            end = time.perf_counter()
            logger.critical(f"Killed ransomware process with PID {process.pid} and it's PPID in {round(end - self.start, 3)}s.")

            for path in process_file_abs_path_list:
                logger.critical(f"Ransomware file is in {path}. Deleting it.")
                try:
                    os.remove(path)
                    secure_flag += 1
                except:
                    pass

            self.checkForNewUsers(user_whitelist)

            if secure_flag == 0:
                logger.critical(f"Ransomware event just happened, but your system is insecure.")

            elif secure_flag == 0:
                logger.critical(f"Ransomware event just happened, but your system might be insecure.")

            elif secure_flag == 2:
                logger.critical(f"Ransomware event just happened, and your system is secure.")

            if gc.auto_restore_system:
                restoreSystem()

        except:
            pass


if __name__ == "__main__":
    pass
else:
    from app.logger import logger
