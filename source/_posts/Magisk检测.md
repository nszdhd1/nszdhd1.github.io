---
title: Magisk检测
date: 2020-03-09 15:50:42
tags: other
---

## Magisk 原理

 ### Xposed 和 Magisk原理图

![image-20200220161119719](https://raw.githubusercontent.com/nszdhd1/nszdhd1.github.io/master/2020/03/09/Magisk%E6%A3%80%E6%B5%8B/image-20200220161119719.png)

### Xposed 原理

详细讲解：https://blog.csdn.net/ascii2/article/details/47974217

Xposed修改了app_process程序，在执行第一个java程序（com.Android.internal.os.ZygoteInit）之前进行截获,改变执行流程，进入到XposedBridge.jar，通过INI方法hookMethodNative指向Native方法xposedCallHandler，xposedCallHandler在转入handleHookedMethod这个Java方法执行用户规定的Hook Func

### xposed 检测方法

##### 1. 检测包名

 检测是否安装de.robv.android.xposed.installer

##### 2.调用栈

抛出一个异常并捕获，将堆栈信息打印出来：

![image-20200220164108776](https://raw.githubusercontent.com/nszdhd1/nszdhd1.github.io/master/2020/03/09/Magisk%E6%A3%80%E6%B5%8B/image-20200220164108776.png)

可以看到每个App是先执行的XposedBridge.jar的main方法，之后再调用的Zygote的main方法。通过检测堆栈中是否包含`Xposed`等字样即可知道是否安装了Xposed

<!-- more -->

##### 3. xposed相关文件

Xposed的组件需要被加载，必然在内存空间留下痕迹，通过遍历/proc/<pid>/maps内容，观察是否加载/system/framework/XposedBridge.jar

##### 4. 检测并且关闭HOOK

在`de.robv.android.xposed.XposedBridge`中有一个`disableHooks`字段用于标记对于当前应用是否要进行hook。通过获取这个字段的值就可以知道是否在我们App上启用hook了，甚至可以通过将其设置为true停掉Xposed。

```java
Field disableHooksFiled = ClassLoader.getSystemClassLoader()
        .loadClass("de.robv.android.xposed.XposedBridge")
        .getDeclaredField("disableHooks");
disableHooksFiled.setAccessible(true);
Object enable = disableHooksFiled.get(null);  // 当前状态
disableHooksFiled.set(null, true);            // 设置为关闭

```



##### 5. 来自支付宝的xposed HOOK检测

 原文地址：https://segmentfault.com/a/1190000009976827

反射获得一个类de.robv.android.xposed.XposedHelpers 的对象，检测obXposedHelper成员fieldCache,methodCache,constructorCache是否有支付宝包的关键字。



### Magisk 原理

网上分析magisk的资料很少，都只说：

Magisk则另辟蹊径，通过挂载一个与系统文件相隔离的文件系统来加载自定义内容，为系统分区打开了一个通往平行世界的入口，所有改动在那个世界（Magisk分区）里发生，在必要的时候却又可以被认为是（从系统分区的角度而言）没有发生过。

就这种程度的原理想检测magisk是不可能的。

因为知道magisk是靠修改boot.img来实现的，找到修改的shell脚本，介绍如下：

![image-20200220172723250](https://raw.githubusercontent.com/nszdhd1/nszdhd1.github.io/master/2020/03/09/Magisk%E6%A3%80%E6%B5%8B/image-20200220172723250.png)

通过阅读脚本，可知：

修改boot.img成功后，会将修改后的镜像添加到系统中去，主要为initialize()、main()函数。

initialize主要做一些检查、加载的工作，根据代码可知，magisk的工作目录在/data/adb/magisk

![image-20200221110120916](https://raw.githubusercontent.com/nszdhd1/nszdhd1.github.io/master/2020/03/09/Magisk%E6%A3%80%E6%B5%8B/image-20200221110120916.png)

main函数主要是安装magisk

![image-20200221112244735](https://raw.githubusercontent.com/nszdhd1/nszdhd1.github.io/master/2020/03/09/Magisk%E6%A3%80%E6%B5%8B/image-20200221112244735.png)

对main函数中的每个函数进行粗略的分析，mount_partitions主要是获取root权限，然后挂载一些自己的东西到系统

```shell
mount_partitions() {
  # Check A/B slot
  SLOT=`grep_cmdline androidboot.slot_suffix`
  if [ -z $SLOT ]; then
    SLOT=`grep_cmdline androidboot.slot`
    [ -z $SLOT ] || SLOT=_${SLOT}
  fi
  [ -z $SLOT ] || ui_print "- Current boot slot: $SLOT"

  # Mount ro partitions
  mount_ro_ensure system
  if [ -f /system/init.rc ]; then
    SYSTEM_ROOT=true
    [ -L /system_root ] && rm -f /system_root
    mkdir /system_root 2>/dev/null
    mount --move /system /system_root
    mount -o bind /system_root/system /system
  else
    grep ' / ' /proc/mounts | grep -qv 'rootfs' || grep -q ' /system_root ' /proc/mounts \
    && SYSTEM_ROOT=true || SYSTEM_ROOT=false
  fi
  [ -L /system/vendor ] && mount_ro_ensure vendor
  $SYSTEM_ROOT && ui_print "- Device is system-as-root"

  # Mount persist partition in recovery
  if ! $BOOTMODE && [ ! -z $PERSISTDIR ]; then
    # Try to mount persist
    PERSISTDIR=/persist
    mount_name persist /persist
    if ! is_mounted /persist; then
      # Fallback to cache
      mount_name cache /cache
      is_mounted /cache && PERSISTDIR=/cache || PERSISTDIR=
    fi
  fi
}
```

find_manager_apk顾名思义，它提供了apk可能存在的几个路径：

```shell
find_manager_apk() {
  [ -z $APK ] && APK=/data/adb/magisk.apk
  [ -f $APK ] || APK=/data/magisk/magisk.apk
  [ -f $APK ] || APK=/data/app/com.topjohnwu.magisk*/*.apk
  if [ ! -f $APK ]; then
    DBAPK=`magisk --sqlite "SELECT value FROM strings WHERE key='requester'" 2>/dev/null | cut -d= -f2`
    [ -z $DBAPK ] && DBAPK=`strings /data/adb/magisk.db | grep 5requester | cut -c11-`
    [ -z $DBAPK ] || APK=/data/user_de/*/$DBAPK/dyn/*.apk
    [ -f $APK ] || [ -z $DBAPK ] || APK=/data/app/$DBAPK*/*.apk
  fi
  [ -f $APK ] || ui_print "! Unable to detect Magisk Manager APK for BootSigner"
}
```

install_magisk函数中的run_migrations，主要是将修boot.img.gz文件保存起来：

```shell
run_migrations() {
  local LOCSHA1
  local TARGET
  # Legacy app installation
  local BACKUP=/data/adb/magisk/stock_boot*.gz
  if [ -f $BACKUP ]; then
    cp $BACKUP /data
    rm -f $BACKUP
  fi

  # Legacy backup
  for gz in /data/stock_boot*.gz; do
    [ -f $gz ] || break
    LOCSHA1=`basename $gz | sed -e 's/stock_boot_//' -e 's/.img.gz//'`
    [ -z $LOCSHA1 ] && break
    mkdir /data/magisk_backup_${LOCSHA1} 2>/dev/null
    mv $gz /data/magisk_backup_${LOCSHA1}/boot.img.gz
  done

  # Stock backups
  LOCSHA1=$SHA1
  for name in boot dtb dtbo; do
    BACKUP=/data/adb/magisk/stock_${name}.img
    [ -f $BACKUP ] || continue
    if [ $name = 'boot' ]; then
      LOCSHA1=`$MAGISKBIN/magiskboot sha1 $BACKUP`
      mkdir /data/magisk_backup_${LOCSHA1} 2>/dev/null
    fi
    TARGET=/data/magisk_backup_${LOCSHA1}/${name}.img
    cp $BACKUP $TARGET
    rm -f $BACKUP
    gzip -9f $TARGET
  done
}
```

### Magisk 检测方法

##### 1. 检测是否安装Magisk manager 

检查是否安装包名为 com.topjohnwu.magisk

### 2. Magisk 相关的文件

1.  是否存在magisk的工作目录：/data/adb/magisk

2.  app安装相关目录：
/data/app/com.topjohnwu.magisk、/data/user_de/0/com.topjohnwu.magisk、
/config/sdcardfs/com.topjohnwu.magisk、/data/data/com.topjohnwu.magisk、
/data/media/0/Android/data/com.topjohnwu.magisk、/mnt/runtime/default/emulated/0/Android/data/com.topjohnwu.magisk、
/config/sdcardfs/com.topjohnwu.magisk

3.  magisk运行产生的目录和文件：

   /data/magisk_backup_[md5]、/sbin/magisk、/cache/magisk.log、/mnt/vendor/persist/magisk

4.  所有安装的magisk模块：/data/adb/modules

##### 3.  系统信息

通过遍历`/proc/mounts` 或`/proc/self/mounts`中内容，观察是否有/sbin/magisk路径下的文件被挂载进系统

### 问题

1. 目前magisk的检测方法，仅仅只是检测到手机上有magisk，并不能获得该用户在攻击自己app的证据

### 检测代码示例

```c++
app普通权限下 

std::vector<std::string> p;

//都失败：
    p.push_back("/data/adb/magisk");
    p.push_back("/data/app/com.topjohnwu.magisk");
    p.push_back("/config/sdcardfs/com.topjohnwu.magisk");
    p.push_back("/data/media/0/Android/data/com.topjohnwu.magisk");
    p.push_back("/mnt/runtime/default/emulated/0/Android/data/com.topjohnwu.magisk");
    p.push_back("/config/sdcardfs/com.topjohnwu.magisk");
    p.push_back("/cache/magisk.log");
    p.push_back("/mnt/vendor/persist/magisk");
    p.push_back("/data/adb/modules");
    p.push_back("/config/sdcardfs/com.topjohnwu.magisk/appid");
    p.push_back("/data/adb/magisk/chromeos/kernel.keyblock");
    p.push_back("/data/system/graphicsstats/1582156800000/com.topjohnwu.magisk");
    p.push_back("/data/system_ce/0/shortcut_service/bitmaps/com.topjohnwu.magisk");
    p.push_back("/mnt/runtime/default/emulated/0/Android/data/com.topjohnwu.magisk");
    p.push_back("/mnt/runtime/write/emulated/0/Android/data/com.topjohnwu.magisk");

// access成功 ，open 失败 , stat失败：

    p.push_back("/data/misc/profiles/ref/com.topjohnwu.magisk");
    p.push_back("/data/misc/profiles/cur/0/com.topjohnwu.magisk");

// access成功 stat成功，open 失败：
    p.push_back("/data/user_de/0/com.topjohnwu.magisk");
    p.push_back("/data/data/com.topjohnwu.magisk");

//都成功：
    p.push_back("/sbin/magiskpolicy");
    p.push_back("/sbin/magiskinit");
    p.push_back("/sbin/magiskhide");
    p.push_back("/sbin/magisk");

int openfd = open("/proc/self/mounts",0,O_RDWR);
    LOGE("open fd:  %d",openfd);
    char buff[1024] = {0};

    while (read(openfd,buff,1024)){
        LOGE("%s",buff);
    }


    close(openfd);
```

