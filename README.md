<div align="center">
# SEIG-Auto-Connect

</div>

> [!WARNING]
> 需要您的账号可以在网页端登录

> [!TIP]
> 原则上适用于所有广东的网页版esurfing<br>
> 提示：打包参数：nuitka --standalone --lto=yes --msvc=latest --disable-ccache --windows-console-mode=disable --enable-plugin=pyqt5,upx --upx-binary=F:\Programs\upx\upx.exe  --output-dir=SAC --windows-icon-from-ico=yish.ico --nofollow-import-to=unittest main.py<br>打包完后需要将仓库中的Pyqt5(可能需要)、ddddocr文件夹覆盖进去(必须)，(因为UPX完Pyqt5会损坏，ddddocr没被打包进去)
## 感谢
> 验证码获取和自动获取登陆参数参考了前辈的代码[ESurfingPy-CLI](https://github.com/Pandaft/ESurfingPy-CLI)，自己原本搞得验证码一直过不了服务器

## 使用方式

**开袋即食**


## 特色
- [x] !此工具不会收集您的任何账号密码信息!
- [x] 支持一键登录网页端校园网账号
- [x] 支持自动获取登录参数
- [x] 自动登录功能，在启动软件时自动登录保存的账号
- [x] 自动识别验证码，如果失败5次，需要手动输入验证码
- [x] 看门狗，默认每600秒检测一次网络状态，若网络不通，自动重连
- [x] 对保存的密码低级加密
- [x] 按下最小化按钮可以隐藏进托盘 
- [x] 多拨功能

## TODO
- [ ] 支持更多类型账号登录(技术攻关中...) 
      
## 下载链接
> 最新版下载地址：[蓝奏云下载](https://yish.lanzn.com/b004hx44wb)
密码:6cgi<br>
> 沉梦小站发布地址：[GO！](https://cmxz.top)
>
## 界面图片
> 主界面<br>
<img width="664" alt="80c5bce3c673a84038a1b0167875912" src="https://github.com/user-attachments/assets/415c6e50-a541-4a7b-b33f-8f0d65ad8f99"><br>
> 最小化<br>
![image](https://github.com/user-attachments/assets/4785e962-ed25-4ec3-b13e-a39f6ac465db)

