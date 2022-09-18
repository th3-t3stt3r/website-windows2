def run():
    # Modules imports
    import psutil
    from colorama import init
    from pyfiglet import Figlet
    from termcolor import colored
    import ctypes

    # Files imports
    import app.monitor as Monitor
    import app.honeyfolder_generator as HoneyfolderGenerator
    from app.config import GeneralConfig as gc

    # Start
    adm = ctypes.windll.shell32.IsUserAnAdmin()
    if adm == 0:
        logger.error("Please execute BunnyShield as administrator.")
    else:
        # Set BunnyShield Priority
        psutil.Process(gc.PID).nice(psutil.HIGH_PRIORITY_CLASS)

        init()
        f = Figlet(font='slant')
        print(colored(f.renderText('BunnyShield'), 'magenta'))
        print(colored(f'A Ransomware Detector by Bash Bunny Group  ---  version 1.0.0 for {colored("WINDOWS", "blue")}', 'magenta'))
        logger.debug("Starting BunnyShield Protection.")

        # Get config
        gc.getValues()

        # Generate honeyfolder
        HoneyfolderGenerator.generateHoneyFolder()

        # File Monitor
        logger.debug("Starting BunnyShield Monitor")
        Monitor.start()

        # Quit
        logger.debug("Quitting Bunnyshield.")


if __name__ == "__main__":
    from app.logger import logger
    run()
