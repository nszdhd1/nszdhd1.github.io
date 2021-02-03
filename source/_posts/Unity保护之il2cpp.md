---
title: Unity保护之il2cpp
date: 2020-07-03 11:54:52
tags: protect
---



# IL2CPP 保护方案

##  背景

如果 Unity 游戏 选择使用IL2CPP编译的话，那么会将代码编译到libil2cpp.so，并且将字符串信息保存在一个叫global-metadata.dat的资源文件里。

IL2CPP详细介绍：https://blog.csdn.net/feibabeibei_beibei/artic le/details/95922520

## IL2CPP 加载过程

github上随便找一个使用il2cpp项目的源码，搜索global-metadata.dat，发现只有函数MetadataCache::Initialize()处使用。

```c++
void MetadataCache::Initialize()
{
    s_GlobalMetadata = vm::MetadataLoader::LoadMetadataFile("global-metadata.dat");
    s_GlobalMetadataHeader = (const Il2CppGlobalMetadataHeader*)s_GlobalMetadata;
    ...
        
 }
```

<!-- more -->

查看LoadMetadataFile代码：

```C++
void* MetadataLoader::LoadMetadataFile(const char* fileName)
{
    std::string resourcesDirectory = utils::PathUtils::Combine(utils::Runtime::GetDataDir(), utils::StringView<char>("Metadata"));

    std::string resourceFilePath = utils::PathUtils::Combine(resourcesDirectory, utils::StringView<char>(fileName, strlen(fileName)));

    int error = 0;
    FileHandle* handle = File::Open(resourceFilePath, kFileModeOpen, kFileAccessRead, kFileShareRead, kFileOptionsNone, &error);
    if (error != 0)
        return NULL;

    void* fileBuffer = utils::MemoryMappedFile::Map(handle);

    File::Close(handle, &error);
    if (error != 0)
    {
        utils::MemoryMappedFile::Unmap(fileBuffer);
        fileBuffer = NULL;
        return NULL;
    }

    return fileBuffer;
}
```

很明显，就是Initialize时调用LoadMetadataFile将global-metadata.dat映射到内存中。



关于IL2CPP加载过程，可以参考

http://4ch12dy.site/2019/11/06/unity3d-il2cpp-analyse/unity3d-il2cpp-analyse/

https://www.nevermoe.com/2016/08/10/unity-metadata-loader/

## IL2CPP global-metadata.dat 文件加密及还原

### 1. 加密方式的选择

 暂定 XXTEA

加密工具语言不限

解密放在MPS里，需要使用xxtea-c++版

### 2. 加密文件格式设计

与lua加密相似，内容为 sign+encryptstr。

| 名称       | 释义                                        |
| ---------- | ------------------------------------------- |
| sign       | 可随意设置，长度必须为5                     |
| encryptstr | global-metadata.dat 经过 xxtea 加密后的内容 |

加密示例代码

```python
import xxtea
import os


key = "password"
def encryptfile(infile,outfile):
    fo = open(infile, "rb")
    file = fo.read()
    fo.close()
    fw = open(outfile, "wb")
    enc_str = xxtea.encrypt(file, key)
    sign = r"JJMPS_ENC"
    fw.write(sign.encode())
    fw.write(enc_str)
    fw.close

```

解密示例代码：

```python
#define HOOK_DEF(ret, func, ...) \
  ret (*orig_##func)(__VA_ARGS__); \
  ret new_##func(__VA_ARGS__)


HOOK_DEF(int,fileopen,char * pathname,int flags){

    int fd = orig_fileopen(pathname,flags);
    if(strstr(pathname,"global-metadata.dat")){
        LOGD("file open %s fd %d",pathname,fd);
        return Decrypt_il2cpp(fd);
    }
    return orig_fileopen(pathname,flags);

}

int Decrypt_il2cpp(int fd){
    int flen;
    struct stat statbuff;
    if(fstat(fd, &statbuff) < 0){
        LOGE("fstat error :%s",strerror(errno));
    }else{
        flen = statbuff.st_size;
    }
    LOGD("file size :%d",flen);
    if(flen <= 0){
        return -1;
    }
    int remain = flen % 4096 ? 1 : 0;
    int map_size = (flen / 4096 + remain) * 4096;
    void *data_buffer = (char *) malloc(map_size);
    if (data_buffer == NULL) {
        LOGD("[MpsHook_open] data buffer malloc failed");
        return NULL;
    }
    memset(data_buffer, 0, map_size);
    int data_size = orig_read(fd,data_buffer,flen);

    if (data_size > 0) {

        LOGD("[MpsHook_open] read buffer %d->%d", data_size, map_size);//2530873->2531328

        data_size = map_size;

    } else {

        LOGD("[MpsHook_open] read buffer failed!! %s",strerror(errno));

    }
    lseek(fd, 0, SEEK_SET);
    //do decrypt
    LOGD("data_buffer %p  %s",data_buffer,data_buffer);
    char key[9] = "password";
    size_t len = 0;
    metadata_buffer = xxtea_decrypt(((char *)data_buffer+9),flen-9,key,&len);
    metadata_size = len;

    LOGD("[oook] res: %p %s",len,metadata_buffer);

    char filepath[1024] = "";
    sprintf(filepath,"%s/replace.dat",path); // 创建的文件权限需要注意

    if(access(filepath,F_OK)!=0){
        LOGD("replace.dat not find");
        FILE *fp = fopen(filepath,"wb+");
        if(fp==NULL){
            LOGE("creat file faild %s",strerror(errno));
        } else{
            LOGD("creat file success");
            fclose(fp);
        }
    }
    LOGD("%s",filepath);
    int replace_fd = orig_fileopen(filepath,O_RDWR);
    LOGD("replace_fd %d",replace_fd);
    if(replace_fd<0){
        LOGE("open file %s faild err:%s",filepath,strerror(errno));
    }else{
        int wlen = write(replace_fd,metadata_buffer,metadata_size);

        if(wlen<0){
            LOGE("write file %s faild err:%s ",filepath,strerror(errno));
        }

    }
    metadata_fd = replace_fd;
    orig_close(fd);

    return replace_fd;

}

HOOK_DEF(int,close,int fd){

    if(fd == metadata_fd){
        LOGD("close fd %d",fd);
        metadata_fd = -2;
        char file[1024] = "";
        strcpy(file,path);
        strcat(file,"/replace.dat");
        if(remove(file) == 0){
            LOGD("remove file %s",file);
        } else{
            LOGE("remove file %s  faild",file);
        }
    }
    return orig_close(fd);
}
```

### 3. 其他准备工作

需要在启动时HOOK libc 的 open close 函数，需要注意时机，也要注意hook框架的选择。



### 4. 方案弊端

1. 兼容问题，如果有特殊机型，无法创建或者不能打开替换文件，会导致应用崩溃。

2. 安全性与版本相关，19版加载并没使用libc的mmap，之前的版本攻击者可以hook mmap 来dump文件。

   

### 5. 优势

1. 解决之前方案不支持19版，且该方案能向前兼容。

2. 无法直接分析global-metadata.dat，增加破解者的耗时

   
