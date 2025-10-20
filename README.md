[中文](./README_CN.md) | English
<div align="center">
<a><img src="./Class-Roster-Picker.png" width="180" height="180" alt="Class-Roster-Picker"></a>
</div>

<div align="center">
# SEIG-Auto-Connect
</div>

> [!WARNING]
> To ensure the safety of this project, please avoid sharing it on major public platforms. Use it discreetly.

> [!TIP]
> In principle, this tool is compatible with all web versions of Guangdong's eSurfing<br>
> Tip: Packaging parameters: `nuitka --standalone --lto=yes --msvc=latest --disable-ccache --windows-console-mode=disable --windows-uac-admin --enable-plugin=pyqt5,upx --upx-binary=F:\Programs\upx\upx.exe  --output-dir=SAC --windows-icon-from-ico=yish.ico --nofollow-import-to=unittest main.py`<br>After packaging, you need to copy the `PyQt5` folder from the repo (may be necessary) and **must** copy the `ddddocr` folder into the build (because UPX can damage PyQt5 and `ddddocr` is not bundled)

## Acknowledgements
> The teacher account captcha and auto-login parameter logic references the predecessor [ESurfingPy-CLI](https://github.com/Pandaft/ESurfingPy-CLI), since I couldn't get captcha verification to work on my own<br><br>
> The student login method comes from [ESurfingDialer](https://github.com/Rsplwe/ESurfingDialer), which used unidbg to reuse encryption functions — a very clever solution! I extended it to support custom login IP (though my Java skills are zero, so the code is quite messy, 555)
>
> Both predecessors did amazing work. Perhaps all I did was make their code messier :)

## How to Use

**Plug and play**<br><br>
*Scope*: You need a campus network account. This tool lets you connect using that account, then enable hotspot sharing with no device limit. You can also use the IP binding feature to log in from a router, enabling shared internet access via Wi-Fi. If you have multiple accounts and a multi-dial router, you can even double your speed. With this tool, there's no need for the official client or overpriced cracked routers.<br><br>
*Student Account*: Simply enter your account and password.<br>
*Teacher Account*: Simply enter your account and password.<br><br>

> [!WARNING]
> On first use, disconnect from the campus network so the program can fetch the config automatically!!!<br>

**Watchdog**: Implementation differs by account. Student accounts send heartbeat packets, which act like a built-in watchdog — but the connection drops after shutdown.  
Teacher accounts can use this program's watchdog: every 300s it pings Baidu, and reconnects if the ping fails.<br><br>

**Custom Login IP**: Allows specifying an IP for login. Useful for router multi-dialing or helping a friend connect remotely.  
Note: When using student accounts with custom IPs, you'll see heartbeat errors — because your local machine can't receive server responses sent to the specified IP. This is harmless; it's just a visible error.<br><br>

**Multi-Dialing**: You’ll need a router with multi-dial support to get multiple IPs. Then use the IP feature in this tool to log in.  
Teacher accounts can dial twice. Student accounts currently can only dial once (or hijack a roommate’s). This enables double speed.<br><br>

**Auto Login**: Enable this button to activate both startup auto-launch and auto-login.  
*Note: In version 1.22, auto-start on boot is currently non-functional and pending fix.*

## Features
- [x] **This tool does not collect any account or password data!**
- [x] Supports one-click login and hotspot sharing, bypassing device limits.
- [x] Supports multi-dialing for doubled speed.
- [x] Auto-fetch login parameters.
- [x] Auto-login at startup with saved credentials.
- [x] Teacher accounts auto-recognize captchas. After 5 failures, manual input is needed.
- [x] Watchdog pings every 300s and reconnects if offline.
- [x] Light encryption for stored passwords.
- [x] Minimize-to-tray support.

## TODO
- [x] Support more account types (done in 1.0...) 

## Download Links
> https://github.com/Yish1/SEIG-Auto-Connect/releases<br>
> China mirror: https://www.123865.com/s/8ks9jv-xSJzH? Code: `seig`

## UI Screenshots
> Main interface<br>
![49c00fe212deeb7918d62e90cdda5415](https://github.com/user-attachments/assets/6b11042f-811d-4aae-a2d0-822faccc5daa)<br>
> Minimized view<br>
![image](https://github.com/user-attachments/assets/4785e962-ed25-4ec3-b13e-a39f6ac465db)
