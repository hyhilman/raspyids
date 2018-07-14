import time
import logging

def init():
    # create logger with 'spam_application'
    logger = logging.getLogger('app')
    logger.setLevel(logging.WARNING)

    # create file handler which logs even debug messages
    fh = logging.FileHandler('/var/log/app-raspyids.log')
    fh.setLevel(logging.DEBUG)

    # create console handler with a higher log level
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)

    # create formatter and add it to the handlers
    formatter = MyIDSFormatter()
    fh.setFormatter(formatter)
    ch.setFormatter(formatter)

    # add the handlers to the logger
    logger.addHandler(fh)
    logger.addHandler(ch)

# Custom formatter
class MyIDSFormatter(logging.Formatter):
    def __init__(self, fmt='%(name)s-%(asctime)s: %(message)s', datefmt='%D-%H:%M:%S'):
        logging.Formatter.__init__(self, fmt=fmt, datefmt=datefmt)

    def format(self, record):
        fmt_origin = self._style._fmt
        if record.levelno in (logging.WARNING, logging.ERROR, logging.CRITICAL):
            self._style._fmt = '%(levelname)s-%(asctime)s\n  ' + fmt_origin + \
                               '\n  tracefile: %(pathname)s:%(lineno)d'
        result = super(MyIDSFormatter, self).format(record)
        self._style._fmt = fmt_origin
        return result
