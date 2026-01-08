import os
from models import state


class ConfigManager:
    def __init__(self, config_dir=None):
        appdata_dir = os.getenv("APPDATA")
        config_dir = config_dir or os.path.join(appdata_dir, "SAC")
        os.makedirs(config_dir, exist_ok=True)
        self.config_path = os.path.join(config_dir, "config.ini")
        if not os.path.exists(self.config_path):
            with open(self.config_path, 'w', encoding='utf-8') as file:
                file.write("")
        print(f"配置文件路径: {self.config_path}")

    def read_config(self):
        config = {}
        with open(self.config_path, 'r', encoding='utf-8') as file:
            for line in file:
                if '=' in line:
                    key, value = line.strip().split('=', 1)
                    config[key.strip('[]')] = value.strip()
        try:
            state.username = config.get('username') if config.get('username') else self.update_config("username", "", "w!")
            state.password = config.get('password') if config.get('password') else self.update_config("password", "", "w!")
            state.wlanacip = str(config.get('wlanacip')) if config.get('wlanacip') else self.update_config("wlanacip", "0.0.0.0", "w!")
            state.wlanuserip = str(config.get('wlanuserip')) if config.get('wlanuserip') else self.update_config("wlanuserip", "0.0.0.0", "w!")
            state.esurfingurl = str(config.get('esurfingurl')) if config.get('esurfingurl') else self.update_config("esurfingurl", "0.0.0.0:0", "w!")
            state.save_pwd = config.get('save_pwd') if config.get('save_pwd') else self.update_config("save_pwd", "1", "w!")
            state.auto_connect = config.get('auto_connect') if config.get('auto_connect') else self.update_config("auto_connect", "0", "w!")
            state.watch_dog_timeout = int(config.get('watch_dog_timeout')) if config.get('watch_dog_timeout') else self.update_config("watch_dog_timeout", 300, "w!")
            state.mulit_login = int(config.get('mulit_login')) if config.get('mulit_login') else self.update_config("mulit_login", "1", "w!")
            state.login_mode = int(config.get('login_mode')) if config.get('login_mode') else self.update_config("login_mode", "0", "w!")
        except Exception:
            try:
                os.remove(self.config_path)
            except Exception:
                pass
            with open(self.config_path, 'w', encoding='utf-8') as file:
                file.write("")
            return self.read_config()
        return config

    def update_config(self, variable, new_value, mode=None):
        lines = []
        with open(self.config_path, 'r+', encoding='utf-8') as file:
            lines = file.readlines()

        updated = False
        seen_keys = set()

        for i in range(len(lines)):
            if not lines[i].endswith('\n'):
                lines[i] += '\n'
            if not lines[i].startswith('['):
                lines[i] = ''

        for i, line in enumerate(lines):
            if '=' in line:
                key, value = line.strip().split('=', 1)
                key = key.strip('[]')
                value = value.strip()

                if not value:
                    lines[i] = ''
                    continue

                if key == variable:
                    if new_value:
                        lines[i] = f"[{key}]={new_value}\n"
                        updated = True
                    else:
                        lines[i] = ''

                    if key in seen_keys:
                        lines[i] = ''
                    seen_keys.add(key)

                elif key in seen_keys:
                    lines[i] = ''
                else:
                    seen_keys.add(key)

        if not updated and new_value:
            lines.append(f"[{variable}]={new_value}\n")

        lines = [line for line in lines if line.strip()]

        with open(self.config_path, 'w+', encoding='utf-8') as file:
            file.writelines(lines)

        if mode != "w!":
            self.read_config()

        # print(f"配置项更新: {variable} = {new_value}")

        return new_value
