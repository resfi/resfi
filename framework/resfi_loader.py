"""
    ResFi loader module

    Copyright (C) 2016 Sven Zehl, Anatolij Zubow, Michael Doering, Adam Wolisz

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
    {zehl, zubow, wolisz, doering}@tkn.tu-berlin.de
"""

__author__ = 'zehl, zubow, wolisz, doering'

import logging
import os
import sys
import re
import importlib
import abc
import time
import socket
from agent import ResFiAgent
import config

"""
The main entry point for ResFI: starts the ResFi agent and registers all apps (applications).
"""
class ResFiLoader():
    def __init__(self, log, nodeID):
        self.log = log
        self.resfiAgent = ResFiAgent(log)

        # load all available resfi apps under the apps directory
        apps = self.loadResfiApps()

        self.appThreads = []
        for app in apps:
            self.log.debug(dir(app))
            # start each ResFi app in seperate thread
            appInstance = app.ResFiApp(log, self.resfiAgent)
            appInstance.daemon = True
            appInstance.start()
            self.appThreads.append(appInstance)

        self.log.info('ResFiLoader started...')

    def loadResfiApps(self):
        pysearchre = re.compile('.py$', re.IGNORECASE)
        appfiles = filter(pysearchre.search,
                               os.listdir(os.path.join(os.path.dirname(__file__),
                                                     'apps')))
        form_module = lambda fp: '.' + os.path.splitext(fp)[0]
        apps = map(form_module, appfiles)
        # import parent module / namespace
        importlib.import_module('apps')
        modules = []
        for app in apps:
                 if not app.startswith('.__'):
                     modules.append(importlib.import_module(app, package="apps"))

        return modules

    def wait(self):
        while True:
            time.sleep(0.1)

    def stop(self):
        for appThr in self.appThreads:
            appThr.terminate()

        self.log.info('ResFiLoader terminated...')

if __name__ == "__main__":

    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    # create console handler and set level to info
    handler = logging.StreamHandler()
    handler.setLevel(logging.INFO)
    formatter = logging.Formatter("%(levelname)s - %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    # create error file handler and set level to error
    handler = logging.FileHandler(os.path.join(config.LOGGING_PATH, "resfi_error.log"),"w", encoding=None, delay="true")
    handler.setLevel(logging.ERROR)
    formatter = logging.Formatter("%(levelname)s - %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    # create debug file handler and set level to debug
    handler = logging.FileHandler(os.path.join(config.LOGGING_PATH, "resfi_all.log"),"w")
    handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter("%(levelname)s - %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    # that's it
    nodeID = socket.getfqdn()
    rfLoader = ResFiLoader(logger, nodeID)

    # run forever
    rfLoader.wait()

    #time.sleep(3)
    # stop all apps
    #rfLoader.stop()

