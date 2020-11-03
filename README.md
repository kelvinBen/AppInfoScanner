### AppInfoScanner

一款适用于(Android、iOS、WEB、H5、静态网站)，信息检索的工具，可以帮助渗透测试人员快速获取App或者WEB中的有用资产信息。

### 适用场景
- 日常渗透测试中对APP中的URL地址、IP地址、关键信息进行采集
- 大型攻防演练场景中对APP中URL地址、IP地址、关键信息进行采集
- 对WEB网站源代码进行URL地址、IP地址、关键信息进行采集(可以是开源的代码也可以是右击网页源代码另存为)


### 功能介绍:
- 支持目录批量扫描
- 支持DEX、APK、IPA、HTML、JS、Smali等文件的静态资源采集
- 支持自定义扫描规则
- 支持IP地址信息采集
- 支持URL地址信息采集
- 支持中间件信息采集
- 支持多线程
- 支持忽略资源文件采集
- 支持Android包名采集

### 环境说明

- Apk文件解析需要使用JAVA环境,JAVA版本1.8及以下
- Python3的运行环境

### 目录说明
```
AppInfoScanner
    |-- libs  程序的核心代码
        |-- core
            |-- parses.py 用于解析文件中的静态信息
        |-- task
            |-- base_task.py 统一任务调度
 			|-- android_task.py 用于处理Android相关的文件            
​			 |-- ios_task.py 用于处理iOS相关的文件
​            |-- web_task.py 用于处理Web相关的文件，比如网页右键源代码、H5相关的静态信息
​    |-- tools 程序需要依赖的工具
​        |-- apktool.jar 用于反编译apk文件
​        |-- baksmali.jar 用于反编译dex文件
​        |-- strings.exe 用于windows 32下获取iPA的字符串信息
​        |-- strings64.exe 用于windows 64的系统获取iPA的字符串信息
​    |-- app.py 主运行程序
​    |-- config.py 用于自定义相关规则
​    |-- readme.md  程序使用说明
```



### Android 相关操作说明

#### 扫描指定的apk

```
python3 app.py android -i <Your apk file>  
```

#### 扫描指定的dex

```
python3 app.py android -i <Your dex file> 
```

#### 扫描一个目录下所有的APK或者dex

```
python3 app.py android -i <Your apk or dex directory> 
```

#### 扫描指定关键字(临时)

```
python3 app.py android -i <Your apk or dex directory> -r <the keyword>
```

#### 扫描的时候忽略资源文件

```
python3 app.py android -i <Your apk or dex directory> -n
```

#### 扫描指定包下的内容
```
python3 app.py android -i <Your apk or dex directory> -p <package1.package2>
```

#### 扫描所有的字符串

```
python3 app.py android -i <Your apk or dex directory>  -a
```

#### 指定线程数量

```
python3 app.py android -i <Your apk or dex directory> -t 10
```

### iOS 相关操作说明

#### 扫描指定的iPA文件

```
python3 app.py ios -i <Your ipa file>
```

#### 扫描指定关键字(临时)

```
python3 app.py ios -i <Your ipa file> -r  <the keyword>
```

#### 扫描的时候忽略资源文件

```
python3 app.py ios -i <Your ipa file> -n
```

#### 输出所有的字符串

```
python3 app.py ios -i <Your ipa file> -a
```

#### 指定线程数量

```
python3 app.py ios -i <Your ipa file> -t 10
```

### Web 相关操作说明

#### 扫描指定的Web网站目录或者html相关文件
```
python3 app.py web -i <Your website directory> 
```

#### 扫描指定关键字(临时)

```
python3 app.py web -i  <Your website directory> -r <the keyword>
```

#### 输出所有的字符串
```
python3 app.py web -i  <Your website directory> -a
```


#### 指定线程数量
```
python3 app.py web -i <Your website directory> -t 10
```


### 常见问题

- 1. 信息检索垃圾数据过多？

> 方法1： 根据实际情况调整config.py中的规则信息
> 方法2： 忽略资源文件
