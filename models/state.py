# 全局状态变量，供主程序和各模块导入

version = 1.3
username = None
password = None
esurfingurl = None
wlanacip = None
wlanuserip = None
save_pwd = None
auto_connect = None
watch_dog_timeout = None
login_mode = 0
mulit_login = 1
mulit_info = {}

stop_watch_dog = False
connected = False
jar_login = False
signature = ""
settings_flag = None
retry_thread_started = False
watch_dog_thread_started = False
new_version_checked = False
login_thread_finished = False

# RSA公钥
rsa_public_key = """
    -----BEGIN PUBLIC KEY-----
    MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCyhncn4Z4RY8wITqV7n6hAapEM
    ZwNBP6fflsGs3Ke5g6Ji4AWvNflIXZLNTGIuykoU1v2Bitylyuc9nSKLTvBdcytB
    +4X4CvV4oVDr2aLrXs7LhTNyykcxyhyGhokph0Cb4yR/mybK6OeH2ME1/AZS7AZ4
    pe2gw9lcwXQVF8DJwwIDAQAB
    -----END PUBLIC KEY-----
    """
