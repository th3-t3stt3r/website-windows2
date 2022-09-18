# Modules imports
import os
import random
import time
from fpdf import FPDF

# File imports
from app.logger import logger
from app.config import GeneralConfig as gc


def generateHoneyFolder():
    """Function to create the Honeyfolder with PDFs"""
    start = time.perf_counter()

    if not os.path.exists(gc.PATH_TO_HONEYFOLDER):
        os.mkdir(gc.PATH_TO_HONEYFOLDER)
        logger.debug(f"Creating honeyfolder in {gc.PATH_TO_HONEYFOLDER}.")
        generatePDFs(gc.PATH_TO_HONEYFOLDER)
        end = time.perf_counter()
        logger.debug(f"Created honeyfolder in {round(end - start, 3)}s.")
    else:
        logger.debug(f"Honeyfolder already exists in in {gc.PATH_TO_HONEYFOLDER}. It will not be created a new one.")


def generatePDFs(path):
    random_words = ['secret', 'bank', 'credit-card', 'data', 'password', 'finantial', 'money', 'personal', 'paypal', 'credentials']

    for i1 in range(0, int(gc.pdfs_to_generate / 100)):
        for i2 in range(0, int(gc.pdfs_to_generate / 100)):
            word = random.choice(random_words)
            unique_pdf = FPDF()
            unique_pdf.add_page()
            unique_pdf.set_font('Arial', 'B', 8)
            unique_pdf.cell(40, 10, f'{word}: {i1} - {i2}')
            unique_pdf.output(os.path.join(path, f'{word}-{i1}-{i2}.pdf'), 'F')


def deleteHoneyFolder():
    """Function to delete the Honeyfolder with PDFs"""
    start = time.perf_counter()

    if os.path.exists(gc.PATH_TO_HONEYFOLDER):
        logger.debug(f"Deleting honeyfolder in {gc.PATH_TO_HONEYFOLDER}.")
        for current_path, _, files_in_current_path in os.walk(gc.PATH_TO_HONEYFOLDER):
            try:
                if os.access(current_path, os.W_OK):
                    for file in files_in_current_path:
                        file_absolute_path = os.path.join(current_path, file)
                        os.remove(file_absolute_path)

            except Exception as e:
                logger.error(e)
                continue

        os.rmdir(gc.PATH_TO_HONEYFOLDER)

        end = time.perf_counter()
        logger.debug(f"Deleted honeyfolder in {round(end - start, 3)}s.")

    else:
        logger.debug(f"No honeyfolder detected.")


# MAIN
if __name__ == "__main__":
    pass
else:
    from app.logger import logger
