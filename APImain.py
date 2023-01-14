# #############################################################################
# Author: CobayeGunther
# Creation Date: 26/04/2020
#
# Description:     python script to recreate users from emby to jellyfin
#                 and migrate their watched content
#
# Github Source: https://github.com/CobayeGunther/Emby2Jelly
# Readme Source: https://github.com/CobayeGunther/Emby2Jelly/blob/master/README.md
#
# #############################################################################


import argparse
import getpass
import json
import logging
import requests
import sys
from configparser import ConfigParser


def createConfig(file_obj):
    """
    Create a config file
    """
    config = ConfigParser()
    config["Emby"] = {"EMBY_APIKEY": "aaaabbbbbbbcccccccccccccdddddddd", "EMBY_URLBASE": "http://127.0.0.1:8096/emby/"}

    config["Jelly"] = {
        "JELLY_APIKEY": "eeeeeeeeeeeeeeeffffffffffffffffggggggggg",
        "JELLY_URLBASE": "http://127.0.0.1:8096/jellyfin/",
    }

    config.write(file_obj)


def decode_response(response, log=None):
    if response.status_code == 200:
        try:
            return response.json()
        except Exception:
            return response.text
    else:
        error_text = "(decode_response) Error {http_code} ({reason}): '{output}'".format(
            http_code=response.status_code, output=response.text, reason=response.reason
        )
        if log:
            log.error(error_text)
        else:
            return error_text


class MediaServer(object):
    def __init__(self, apikey, urlbase, log, *args, **kwargs):
        self.apikey = apikey
        self.urlbase = urlbase
        self.log = log
        self.auth_headers = {"accept": "application/json", "api_key": self.apikey}
        self._users = None
        self._selected_users = None

    def get_users_list(self):
        api_url = "{0}Users".format(self.urlbase)
        get_params = {"api_key": self.apikey}

        self.log.debug("Get user list for {}".format(api_url))
        response = requests.get(api_url, headers=self.auth_headers, params=get_params)

        return decode_response(response)

    @property
    def users(self):
        if self._users is None:
            self._users = self.get_users_list()
        return self._users

    @property
    def selected_users(self):
        if self._selected_users is None:
            try:
                self.log.info(self.users.strip())
                return
            except AttributeError:
                pass
            self._selected_users = [user["Name"] for user in self.users]
        return self._selected_users


class Emby(MediaServer):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_watched_status(self):
        migration_data = {}
        # lister les utilsateurs et leur ID respectives
        userCount = 0
        user_total = len(self.users)
        self.log.debug("\033[92mEmby has {0} Users\033[00m".format(user_total))
        user_playlist = {}
        for user in self.users:
            userCount += 1
            if (user["Name"] in self.selected_users) and (user["Name"] is not None):
                migration_data[user["Name"]] = []
                played_item = 0
                self.log.debug("{0} ({2} / {3}): {1}".format(user["Name"], user["Id"], userCount, user_total))

                api_url = "{0}Users/{1}/Items".format(self.urlbase, user["Id"])
                get_params = {
                    "Filters": "IsPlayed",
                    "IncludeItemTypes": "Movie,Episode",
                    "Recursive": "True",
                    "api_key": self.apikey,
                }
                self.log.debug("Get playlist for {}".format(user["Name"]))
                response = requests.get(api_url, headers=self.auth_headers, params=get_params)
                user_playlist = decode_response(response, log=self.log)
                try:
                    for item in user_playlist["Items"]:

                        played_item += 1
                        api_url = "{0}Users/{1}/Items/{2}".format(self.urlbase, user["Id"], item["Id"])
                        self.log.debug("Get itemDto for {}/{}".format(user["Id"], item["Id"]))
                        get_params = {"api_key": self.apikey}
                        response = requests.get(api_url, headers=self.auth_headers, params=get_params)
                        itemDto = decode_response(response, log=self.log)
                        try:
                            itemDto["ProviderIds"].pop("sonarr", None)
                            migration_media = {
                                "Type": item["Type"],
                                "EmbyId": item["Id"],
                                "Name": item["Name"],
                                "ProviderIds": itemDto["ProviderIds"],
                            }
                            migration_data[user["Name"]].append(migration_media)
                        except Exception:
                            pass
                except Exception:
                    pass

        self.log.info("\n\n\033[92m##### EmbySync Done #####\033[00m\n\n")
        return migration_data


class Jelly(MediaServer):
    def __init__(self, new_user_pw, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.new_user_pw = new_user_pw
        self.report_str = []
        self.report = {}

    def compare_users(self, migration_data):
        """
        Compare users in migration_data (the keys) with the users on the server and create the missing ones.
        :returns: the list of created user_names
        """
        self.log.info("\033[96mJelly has {0} Users\033[00m".format(len(self.users)))

        jelly_users_id_dict = {"Name": 0}
        created_users = []

        self.report["users"] = ""
        for jUser in self.users:
            jelly_users_id_dict[jUser["Name"]] = jUser["Id"]
            # Jelly does not accept char space in userNames
        for eUser in migration_data:
            user_name = eUser.replace(" ", "_")
            if user_name in jelly_users_id_dict.keys():
                self.log.debug("Jelly already knows {0} (Id {1})".format(user_name, jelly_users_id_dict[user_name]))
                self.report["users"] += "{0} (Emby) is  {1} (Jelly)\n".format(eUser, user_name)
            else:
                created_users.append(eUser)
                self.log.info("Creating {}".format(eUser))
                api_url = "{0}Users/New".format(self.urlbase)
                get_params = {"api_key": self.apikey}

                self.log.debug("Post user {} for {}".format(user_name, api_url))
                response = requests.post(
                    api_url,
                    headers=self.auth_headers,
                    params=get_params,
                    json={"name": user_name, "Password": self.set_pw(user_name, self.new_user_pw)},
                )
                text = decode_response(response, log=self.log)
                if text:
                    self.log.debug(text)
                    self.report["users"] += "{} on Jelly".format(text)
        return created_users
        # update the jelly Users in case we created any

    """
    ### I originaly wanted to ask Jellyfin server for Any item matching the provider ID of the migration_media,
    ### But it seems the Jellyfin api doesn't implement this (seen this in emby api "documentation")
    def normalise_migration_data():


        #migration_data[user['Name']] = []
        #migration_media={}
        #migration_media['Type']=''
        #migration_media['EmbyId']=''
        #migration_media['Name']=''
        #migration_media['ProviderIds']={}

        nonlocal normalized_migration_data
        #log.debug(self.users)
        for user in self.users:
            if (user['Name'].replace("_"," ") in selected_users):

                normalized_migration_data[user['Name'].replace("_"," ")] = []

                for migration_media in migration_data[user['Name'].replace("_"," ")]:
                    #if type(migration_media['ProviderIds']) != str:
                    self.log.info(migration_media)
                    #migration_data[user['Name'].replace("_"," ")].remove(migration_media)
                    normalisedProviderIds = [
                        "{}.{}".format(k.lower(), v) for k, v in migration_media['ProviderIds'].items()
                    ]
                    self.log.debug("\n".join(normalisedProviderIds))
                    migration_media['ProviderIds'] = ",".join(normalisedProviderIds)
                    normalized_migration_data[user['Name'].replace("_"," ")].append(migration_media)
                    #else:
                    #    continue
    """

    def get_user_library(self, user):
        self.log.debug("getting jelly DB for {0}".format(user["Name"].replace("_", " ")))
        api_url = "{0}Users/{1}/Items".format(self.urlbase, user["Id"])
        get_params = {
            "Recursive": "True",
            "Fields": "ProviderIds",
            "IncludeItemTypes": "Episode,Movie",
            "api_key": self.apikey,
        }
        self.log.debug("Get user library for {}: {}".format(user["Name"], api_url))
        response = requests.get(api_url, headers=self.auth_headers, params=get_params)
        return decode_response(response, self.log)

    def send_watched_status(self, migration_data):
        for user in self.users:
            try:
                user_name = user["Name"].replace("_", " ")
                toSend = len(migration_data[user_name])
                self.report[user_name] = {"ok": 0, "nok": [], "tosend": toSend}

                ok = 0
                nok = 0
                library = self.get_user_library(user)
                for migration_media in migration_data[user_name]:
                    jelly_id = self.search_jelly_library(migration_media, library) or self.search_by_name(
                        migration_media, library
                    )
                    if jelly_id is not None:
                        jelly_headers_movie = {
                            "item": json.dumps(
                                {"Name": migration_media["Name"], "Id": jelly_id, "Played": 1}, separators=(",", ":")
                            ),
                        }
                        jelly_headers_movie.update(self.auth_headers)
                        api_url = "{0}Users/{1}/played_items/{2}".format(self.urlbase, user["Id"], jelly_id)
                        self.log.debug("Update played item for {}: {}".format(user["Name"], api_url))
                        response = requests.post(api_url, headers=jelly_headers_movie, params={"api_key": self.apikey})
                        if decode_response(response, log=self.log) is not None:
                            ok += 1
                            self.report[user_name]["ok"] += 1
                            self.log.debug(
                                "\033[92mOK ! {2}/{3} - {0} has been seen by {1}\n\033[00m".format(
                                    migration_media["Name"], user["Name"], ok, toSend
                                )
                            )
                            # return
                    else:
                        nok += 1
                        self.report[user_name]["nok"].append(migration_media)
                        self.log.error(
                            "Couldn't find Id for {0}\n{1}".format(
                                migration_media["Name"], migration_media["ProviderIds"]
                            )
                        )
            except TypeError:
                # this happens if user["Name"] is None
                pass

    def search_by_name(self, migration_media, Library):
        for jelly_movie in Library["Items"]:
            if jelly_movie["Name"] == migration_media["Name"]:
                self.log.debug("found by name {0}".format(jelly_movie["Name"]))
                return jelly_movie["Id"]
        return None

    def search_jelly_library(self, migration_media, library):
        for item in library["Items"]:
            if item["Type"] != migration_media["Type"]:
                continue

            for it_prov, it_id in item["ProviderIds"].items():
                for prov_name, prov_id in migration_media["ProviderIds"].items():
                    if it_prov.lower() == prov_name.lower() and it_id == prov_id:
                        return item["Id"]
        return None

    def generate_report(self):
        self.report_str.extend(
            ["", "", "", "                      ### Emby2Jelly ###", "", "", self.report["users"], "", ""]
        )
        for user in self.users:
            user_name = user["Name"].replace("_", " ")
            if user_name in self.selected_users:
                self.report_str.append("--- {0} ---".format(user_name))
                self.report_str.append(
                    "Medias Migrated : {0} / {1}".format(self.report[user_name]["ok"], self.report[user_name]["tosend"])
                )
                if self.report[user_name]["nok"] != []:
                    self.report_str.append(
                        "Unfortunately, I Missed {0} Medias :".format(
                            self.report[user_name]["tosend"] - self.report[user_name]["ok"]
                        )
                    )
                    self.report_str.append(list(self.report[user_name]["nok"]))
        with open("RESULTS.txt", "w") as outfile:
            outfile.write("\n".join(self.report_str))
            outfile.close()

    def set_pw(self, u, new_user_pw):
        p1 = "p1"
        p2 = "p2"
        if new_user_pw is not None:
            return new_user_pw
        while 1:
            self.log.info("\nEnter password for user {0}".format(u))
            p1 = getpass.getpass(prompt="Password : ")
            p2 = getpass.getpass(prompt="confirm   : ")
            if p1 == p2:
                if p1 == "":
                    self.log.warning("Warning ! Password is set to empty !")
                return p1
            else:
                self.log.error("passwords does not match \n")


def setup_logging(app_name, verbose, quiet):
    log = logging.getLogger(app_name)
    stdout_handler = logging.StreamHandler(sys.stdout)
    log.addHandler(stdout_handler)
    if verbose:
        loglevel = logging.DEBUG
    elif quiet:
        loglevel = logging.ERROR
    else:
        loglevel = logging.INFO
    log.setLevel(loglevel)
    return log


def parse_args(argv):
    parser = argparse.ArgumentParser(description="Migrate from Emby to Jellyfin (or Jellyfin to Jellyfin)")
    parser.add_argument(
        "--config",
        "-c",
        default="settings.ini",
        type=argparse.FileType("r"),
        help="Config file to read endpoints and API keys, See README",
    )
    g = parser.add_mutually_exclusive_group()
    g.add_argument(
        "--tofile",
        "-t",
        type=argparse.FileType("w"),
        help="run the script saving viewed statuses to a file instead of sending them to destination server",
    )
    g.add_argument(
        "--fromfile",
        "-f",
        type=argparse.FileType("r"),
        help="run the script with a file as source server and send viewed statuses to destination serve",
    )
    parser.add_argument("--new-user-pw", "-p")
    g = parser.add_mutually_exclusive_group()
    g.add_argument("-q", "--quiet", action="store_true")
    g.add_argument("-v", "--verbose", action="store_true")
    cfg = parser.parse_args(argv)
    cfg.log = setup_logging(__name__, cfg.verbose, cfg.quiet)
    return cfg


def main(argv=None):
    migration_data = {}
    selected_users = []

    argv = sys.argv[1:] if argv is None else argv
    cfg = parse_args(argv)
    app_config = ConfigParser()
    app_config.read_file(cfg.config)
    cfg.log.debug(
        "Config from {}: {}".format(cfg.config.name, {s: app_config.options(s) for s in app_config.sections()})
    )

    migration_file = None

    if cfg.tofile is not None:
        cfg.log.info("Migration to file '{}'".format(cfg.tofile.name))
        migration_file = cfg.tofile

    elif cfg.fromfile is not None:
        cfg.log.info("Migration from file '{}'".format(cfg.fromfile.name))
        file_content = None
        migration_file = cfg.fromfile
        try:
            file_content = migration_file.read()
            cfg.log.debug("Read '{}' from file".format(file_content))
            migration_data = json.loads(file_content)
        except Exception as e:
            cfg.log.error("Error reading or decoding file {} content '{}': {}".format(cfg.tofile, file_content, e))
            return 1
    else:
        cfg.log.debug("No file specified: will run from source server to destination server")

    if cfg.fromfile is None:
        emby = Emby(
            selected_users=selected_users,
            log=cfg.log,
            apikey=app_config["Emby"]["EMBY_APIKEY"],
            urlbase=app_config["Emby"]["EMBY_URLBASE"],
        )
        migration_data = emby.get_watched_status()
        if cfg.tofile is not None:
            migration_file.write(json.dumps(migration_data))
            migration_file.close()
            return 0

    if cfg.tofile is None:
        jelly = Jelly(
            new_user_pw=cfg.new_user_pw,
            selected_users=selected_users,
            log=cfg.log,
            apikey=app_config["Jelly"]["JELLY_APIKEY"],
            urlbase=app_config["Jelly"]["JELLY_URLBASE"],
        )
    jelly.send_watched_status(migration_data)
    created_users = jelly.compare_users(migration_data)
    cfg.log.info("{} users have been created: {}".format(len(created_users), created_users))
    jelly.generate_report()
    if migration_file is not None:
        migration_file.close()
    return 0


if __name__ == "__main__":
    main()
