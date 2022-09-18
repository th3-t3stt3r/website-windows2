# Modules imports
import json
import os
from dataclasses import dataclass

# Files imports
from app.logger import logger


@dataclass
class GeneralConfig():

    # MISC
    PID = os.getpid()
    HONEYFOLDER_NAME = "Bunnyshield PDFs"

    # PATHS
    PATH_TO_MAIN_FOLDER = os.getcwd()
    PATH_TO_CONFIG_FOLDER = os.path.join(PATH_TO_MAIN_FOLDER, "config")
    PATH_TO_UTILS_FOLDER = os.path.join(PATH_TO_MAIN_FOLDER, "utils")
    PATH_TO_USER_FOLDER = os.environ['USERPROFILE']
    PATH_TO_HONEYFOLDER = os.path.join(PATH_TO_USER_FOLDER, HONEYFOLDER_NAME)
    PATH_TO_APPDATA = os.path.join(os.environ['USERPROFILE'], 'AppData')
    PATH_TO_TEMP = os.environ['TEMP']

    # FILE EXT
    FILE_EXT_LIST = [line.rstrip() for line in open(os.path.join(PATH_TO_UTILS_FOLDER, "file_extensions.txt"))]

    # REGEX
    LAST_FILE_PATTERN = "([^\\\]+$)"

    # MONITOR
    selected_directories = [
        "C:\\Users"
    ]

    # INTERVALS
    event_count_trigger = 30
    unknow_extension_event_count_trigger = 3
    check_ransom_time = 3
    time_to_check_io = 1
    pdfs_to_generate = 10000
    auto_restore_system = False

    def getValues():
        if not os.path.exists(GeneralConfig.PATH_TO_CONFIG_FOLDER):
            os.mkdir(os.path.join(GeneralConfig.PATH_TO_MAIN_FOLDER, 'config'))

        if not os.path.exists(os.path.join(GeneralConfig.PATH_TO_CONFIG_FOLDER, 'config.json')):
            config_dict = {

                "event_count_trigger": GeneralConfig.event_count_trigger,
                "unknow_extension_event_count_trigger": GeneralConfig.unknow_extension_event_count_trigger,
                "check_ransom_time": GeneralConfig.check_ransom_time,
                "time_to_check_io": GeneralConfig.time_to_check_io,
                "pdfs_to_generate": GeneralConfig.pdfs_to_generate,
                "auto_restore_system": GeneralConfig.auto_restore_system


            }

            json_object = json.dumps(config_dict, indent=4)

            with open(os.path.join(GeneralConfig.PATH_TO_CONFIG_FOLDER, 'config.json'), 'w') as f:
                f.write(json_object)

        else:
            while True:
                with open(os.path.join(GeneralConfig.PATH_TO_CONFIG_FOLDER, 'config.json')) as f:
                    json_file_data = json.load(f)

                modified_flag = 0
                for key, value in json_file_data.items():
                    if key == 'event_count_trigger':
                        GeneralConfig.event_count_trigger = value
                        modified_flag += 1
                    elif key == 'unknow_extension_event_count_trigger':
                        GeneralConfig.unknow_extension_event_count_trigger = value
                        modified_flag += 1
                    elif key == 'check_ransom_time':
                        GeneralConfig.check_ransom_time = value
                        modified_flag += 1
                    elif key == 'time_to_check_io':
                        GeneralConfig.time_to_check_io = value
                        modified_flag += 1
                    elif key == 'pdfs_to_generate':
                        GeneralConfig.pdfs_to_generate = value
                        modified_flag += 1
                    elif key == 'auto_restore_system':
                        GeneralConfig.auto_restore_system = value
                        modified_flag += 1

                if modified_flag < 6:
                    logger.error('Could not get alll configs from config.json. The file will be recreated and everything will be set to default.')
                    GeneralConfig.event_count_trigger = 30
                    GeneralConfig.unknow_extension_event_count_trigger = 3
                    GeneralConfig.check_ransom_time = 3
                    GeneralConfig.time_to_check_io = 1
                    GeneralConfig.pdfs_to_generate = 10000
                    GeneralConfig.auto_restore_system = False

                else:
                    logger.debug('All configs have been set by config.json file.')
                    break


if __name__ == "__main__":
    pass
else:
    pass
