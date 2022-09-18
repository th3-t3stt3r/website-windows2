from datetime import datetime
import os
import subprocess
import psutil
from app.config import GeneralConfig as gc
from app.logger import logger


def windowsConfig(user_whitelist, action):
    if action == 'check':
        # vssadmin.exe
        try:
            logger.debug(f'Checking for vssadmin.exe config.')

            subprocess.check_output(
                ['powershell.exe', f'takeown /A /F C:\Windows\System32\BunnyshieldV.exe'],
                shell=True, stderr=subprocess.DEVNULL)

            for user in user_whitelist:
                subprocess.check_output(
                    ['powershell.exe', f'icacls C:\Windows\System32\BunnyshieldV.exe /grant "{user}:(F,M,RX,R,W)"'],
                    shell=True, stderr=subprocess.DEVNULL)

            subprocess.check_output(
                ['powershell.exe', f'ren C:\Windows\System32\BunnyshieldV.exe vssadmin.exe'],
                shell=True, stderr=subprocess.DEVNULL)

            logger.debug(f'Sucessfully checked for vssadmin.exe config.')

        except:
            logger.error('Could not check vssadmin.exe config.')

        # wmic.exe
        try:
            logger.debug(f'Checking for WMIC.exe config.')

            subprocess.check_output(
                ['powershell.exe', f'takeown /A /F C:\Windows\System32\wbem\BunnyshieldW.exe'],
                shell=True, stderr=subprocess.DEVNULL)

            for user in user_whitelist:
                subprocess.check_output(
                    ['powershell.exe', f'icacls C:\Windows\System32\wbem\BunnyshieldW.exe /grant "{user}:(F,M,RX,R,W)"'],
                    shell=True, stderr=subprocess.DEVNULL)

            subprocess.check_output(
                ['powershell.exe', f'ren C:\Windows\System32\wbem\BunnyshieldW.exe WMIC.exe'],
                shell=True, stderr=subprocess.DEVNULL)

            logger.debug(f'Sucessfully checked for WMIC.exe config.')

        except:
            logger.error('Could not check for WMIC.exe config.')

    if action == 'set':
        # vssadmin.exe
        try:
            logger.debug(f'Appling configs to vssadmin.exe.')

            subprocess.check_output(
                ['powershell.exe', f'takeown /A /F C:\Windows\System32\\vssadmin.exe'],
                shell=True, stderr=subprocess.DEVNULL)

            for user in user_whitelist:
                subprocess.check_output(
                    ['powershell.exe', f'icacls C:\Windows\System32\\vssadmin.exe /grant "{user}:(F,M,RX,R,W)"'],
                    shell=True, stderr=subprocess.DEVNULL)

            subprocess.check_output(
                ['powershell.exe', f'ren C:\Windows\System32\\vssadmin.exe BunnyshieldV.exe'],
                shell=True, stderr=subprocess.DEVNULL)

            for user in user_whitelist:
                subprocess.check_output(
                    ['powershell.exe', f'icacls C:\Windows\System32\BunnyshieldV.exe /deny "{user}:(F,M,RX,R,W)"'],
                    shell=True, stderr=subprocess.DEVNULL)

            subprocess.check_output(
                ['powershell.exe', f'net stop VSS'],
                shell=True, stderr=subprocess.DEVNULL)

            logger.debug(f'Sucessfully applied configs to vssadmin.exe and renamed to BunnyshieldV.exe.')

        except:
            logger.error('Could not apply vssadmin.exe config.')

        # wmic.exe
        try:
            logger.debug(f'Appling configs to WMIC.exe.')

            subprocess.check_output(
                ['powershell.exe', f'takeown /A /F C:\Windows\System32\wbem\WMIC.exe'],
                shell=True, stderr=subprocess.DEVNULL)

            for user in user_whitelist:
                subprocess.check_output(
                    ['powershell.exe', f'icacls C:\Windows\System32\wbem\WMIC.exe /grant "{user}:(F,M,RX,R,W)"'],
                    shell=True, stderr=subprocess.DEVNULL)

            subprocess.check_output(
                ['powershell.exe', f'ren C:\Windows\System32\wbem\WMIC.exe BunnyshieldW.exe'],
                shell=True, stderr=subprocess.DEVNULL)

            for user in user_whitelist:
                subprocess.check_output(
                    ['powershell.exe', f'icacls C:\Windows\System32\wbem\BunnyshieldW.exe /deny "{user}:(F,M,RX,R,W)"'],
                    shell=True, stderr=subprocess.DEVNULL)

            logger.debug(f'Sucessfully applied configs to WMIC.exe and renamed to bunnyshieldW.exe.')

        except:
            logger.error('Could not apply WMIC.exe config.')


def restorePoint():
    logger.debug(f'Checking for restore point creation')

    try:
        subprocess.check_output(
            ['powershell.exe', f'net start VSS'],
            shell=True, stderr=subprocess.DEVNULL)
    except:
        pass

    disk_list = []
    for disk in psutil.disk_partitions():
        disk_list.append(f'{disk.device}\\')
    disk_list = '"' + '", "'.join((str(e) for e in disk_list)) + '"'

    try:
        subprocess.check_output(
            ['powershell.exe', f'Enable-ComputerRestore -Drive {disk_list}'],
            shell=True, stderr=subprocess.DEVNULL)
    except:
        pass

    create_restore_point = False
    restore_point_txt_path = os.path.join(gc.PATH_TO_CONFIG_FOLDER, 'restorepointtime.txt')
    current_date = datetime.now().strftime("%d-%m-%Y %H:%M:%S")
    current_date_obj = datetime.strptime(current_date, "%d-%m-%Y %H:%M:%S")

    if not os.path.exists(restore_point_txt_path):
        with open(restore_point_txt_path, 'w') as f:
            f.write(current_date)

    with open(restore_point_txt_path, 'r') as f:
        last_restore_point_date = f.read()
        last_restore_point_date_obj = datetime.strptime(last_restore_point_date, "%d-%m-%Y %H:%M:%S")

        if (current_date_obj - last_restore_point_date_obj).days > 1:
            create_restore_point = True

    if create_restore_point:
        try:
            logger.debug(f'Creating restore point for {current_date}')
            subprocess.check_output(
                ['powershell.exe', f'Checkpoint-Computer -Description "BunnyShieldRestorePoint" -RestorePointType "MODIFY_SETTINGS"'],
                shell=True, stderr=subprocess.DEVNULL)

            with open(restore_point_txt_path, 'w') as f:
                f.write(datetime.now().strftime("%d-%m-%Y %H:%M:%S"))

        except Exception as e:
            print(e)
            logger.error('Could not create restore point')
            pass
    else:
        logger.debug(f'There is no need to create a new restore point')


def restoreSystem():
    if gc.auto_restore_system:
        last_restore_number = subprocess.check_output(
            ['powershell.exe', '((Get-ComputerRestorePoint).SequenceNumber)[-1]'],
            shell=True, stderr=subprocess.DEVNULL).decode().rstrip()

        subprocess.check_output(
            ['powershell.exe', f'Restore-Computer -RestorePoint {last_restore_number}'],
            shell=True, stderr=subprocess.DEVNULL)


def getUsers():
    users = subprocess.check_output(
        ['powershell.exe', 'Get-LocalUser | Select-Object -Property Name | Format-Table -hidetableheaders'],
        shell=True, stderr=subprocess.DEVNULL).decode().split('\n')
    users = [user.rstrip() for user in users]
    for i in range(0, 100):
        try:
            users.remove('')
        except:
            pass

    return users
