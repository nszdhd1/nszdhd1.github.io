---
title: Unity保护之assetbundle
date: 2020-07-03 11:55:02
tags: protect
---



# AssetBundle加密

#### 1.简介

##### 1.1 什么是AssetBundle

AssetBundle是Unity pro提供的一种用来存储资源的文件格式，它可以存储任意一种Unity引擎能够识别的资源，如Scene、Mesh、Material、Texture、Audio、noxss等等，同时，AssetBundle也可以包含开发者自定义的二进制文件，只需要将自定义文件的扩展名改为.bytes，Unity就可以把它识别为TextAsset，进而就可以被打包到AssetBundle中。Unity引擎所能识别的资源我们称为Asset，AssetBundle就是Asset的一个集合。

AssetBundle 加载，可分为请求服务器和本地资源，一般Assetbundle静态文件，

##### 1.2 AssetBundle的特点

压缩（缺省）、动态载入、本地缓存

#####  1.3 AssetBundle 使用（开发视角）

a、创建AssetBundle，并打包；

b、上传到Server；

c、游戏运行时根据需要下载（或者从本地cache中加载）AssetBundle文件；

d、解析加载Assets；

e、使用完毕后释放；

将资源文件打包成ab包，在unity里使用：

**BuildPipeline.BuildAssetBundles（string outputPath, BuildAssetBundleOptions assetBundleOptions, BuildTarget targetPlatform）**

加载静态ab文件，在unity里使用（从服务器下载没有静态文件，暂不考虑）：

**AssetBundle.Load (name : string)** 

<!-- more -->

#### 2.加密

##### 2.1  文件加密格式

加密后的文件内容为 sign + enc_str

| 名称    | 释义                                          |
| ------- | --------------------------------------------- |
| sign    | 长度固定用于替换文件头（ab包文件头为UnityFS） |
| enc_str | 经过 异或后的内容                             |

##### 2.2 加密代码

```python
def xor_encrypt(tips,key):
    ltips=len(tips)
    lkey=len(key)
    secret=[]
    num=0
    for each in tips:
        if num>=lkey:
            num=num%lkey
        secret.append( chr( each^ord(key[num]) ) )
        num+=1
    return "".join(secret)

def encryptfile(infile,outfile):
    if (os.path.splitext(outfile)[1] != ".ab"):
        return
    fo = open(infile, "rb")
    file = fo.read()
    fo.close()
    if(file[0:7]!= b"UnityFS"):
        return
    fw = open(outfile, "wb")
    fw.write(b"AAAAAAA")
    enc = xor_encrypt(file[7:],key)
    for i in enc:
        a = struct.pack("B",ord(i))
        fw.write(a)
    fw.close
```

#### 3. 解密（旧版）

##### 3.1 解密代码

通过 hook libc 中的read函数 实现 ，过程如下：

1. 通过文件名判断文件是否为ab包
2. 记录此时文件读取的偏移，读取文件头
3. 根据文件头判断文件是否需要解密
4. 解密文件内容，并返回

```c++
/**
 *   通过读取文件开头的7位来判断文件是否加密
 * */
bool is_encryptfile(int fd){
    int ret  = false;

    off_t offset = lseek(fd,0,SEEK_CUR);
    lseek(fd, 0, SEEK_SET);
    char buff[10];
    if(old_read(fd,buff,7)){
        buff[7] = '\0';
        if(strstr(buff,"AAAAAAA") != NULL){
            ret =  true;
        }
    }else{
        char str[1024] = {'\0'};
        char file_path[1024] = {'\0'};
        sprintf(str, "/proc/self/fd/%d", fd);
        readlink(str,file_path,sizeof(file_path)-1);
        MLOGE("read fd %d  name %s faild err %s",fd,file_path,strerror(errno));
    }

    lseek(fd, offset, SEEK_SET);
    return ret;
}

int (*old_read)(int fd, void *buf, int count);
int new_read(int fd, void *buf, int count){

    off_t offset = lseek(fd,0,SEEK_CUR);
    if(is_encryptfile(fd)){
        if(offset<7 && count+offset<=7){
            char *head = "UnityFS";
            memcpy(buf,head+offset,count);
            lseek(fd, offset+1, SEEK_SET);
            MLOGD("read buf1 %s",buf);
            return count;
        } else{
            char *filedata = (char *)malloc(count* sizeof(char));
            char key[5] = "OOOK";
            lseek(fd, offset, SEEK_SET);
            int readlen = old_read(fd,filedata,count);
            if(count == readlen){
                for(int i = 0;i<count;i++){
                    MLOGD("read buf[%d] 0x%x  ",offset+i,filedata[i]);
                    filedata[i] = filedata[i] ^ key[(offset-7 +i)%4];
                    MLOGD("read buf[%d] 0x%x  %c  0x%x",offset+i,filedata[i],key[(offset-7+i)%4],key[(offset-7+i)%4]);
                }
                memcpy(buf,filedata,count);
            }
            delete(filedata);
            lseek(fd, offset+count, SEEK_SET);
            return readlen;
        }
    }

    return old_read(fd,buf,count);



}
```

##### 3.2 注意事项

1. 解密后的文件长度必须和加载时的文件长度一致，不然会因为长度不一致导致C#报错文件流以外终止

2. key可以随意设置，不限内容长度。

3. ab包加载调用read函数时count 与lua 加载 count是文件长度不同，ad包加载，根据文件格式读取8位4位或者1位。

   



#### 5. 解密（新版）

##### 5.1 加载概述

旧版加载ab包是直接使用read读取文件，而新版是通过解压base.apk来获取ab包文件。

主要函数包括：ZipFile::inflateRead、ZipFile::read、ZipFile::seek，其中read、seek都通过调用inflateread来实现，inflateread函数通过循环inflate函数实现，读取文件内容是通过ZipFile::read。

##### 5.2 解密代码

```c++
void *readbuf;
uLong offset_start = 0;
uLong offset_end = 0;
int now_count = 0;


char key[11] = "jjmatch123";

HOOK_DEF(int,read,int fd,void *buf,int count){

    off_t offset = lseek(fd,0,SEEK_CUR);

    if(offset_end!=0&&offset_start!=0){ //  读取目标文件解压前内容，并记录
        if(offset<=offset_end&&offset>=offset_start){
            readbuf = buf;
            now_count = count;
        }
    }

    int ret = orig_read(fd,buf,count);

    InitZIPfileInfo(fd,count,buf,offset); // 新版

    return ret;
}

int InitZIPfileInfo(int fd,int count,void *buf,uLong offset){

    if(fd == 0 || count != 30){  //频繁调用，不宜使用log
        return 0;
    }

    if(sizeof(ZIPfile) != 30){
        LOGE("[AssetBundleDecryptor::InitZIPfileInfo] sizeof(ZIPfile) is not 30!");
        return -1;
    }


    ZIPfile *ziphead = static_cast<ZIPfile *>(buf);

    if(ziphead->frSignature[0] == 0x50 &&
       ziphead->frSignature[1] == 0x4b &&
       ziphead->frSignature[2] == 0x03 &&
       ziphead->frSignature[3] == 0x04
            ){


        char *filename= (char *)malloc(sizeof(char)*ziphead->frFileNameLength+1);

        int off = lseek(fd,0,SEEK_CUR);

        int ret = orig_read(fd,filename,ziphead->frFileNameLength);

        if(ret == -1){
            LOGE("[AssetBundleDecryptor::InitZIPfileInfo] read error %s",strerror(errno));
            return -1;
        }

        LOGD("[AssetBundleDecryptor::InitZIPfileInfo] FileName %*s",ziphead->frFileNameLength,filename);

        if(strstr(filename,"mod.ab") != NULL){  // 判断文件是否需要解密


            LOGD("[AssetBundleDecryptor::InitZIPfileInfo] zipfile info UncompressedSize:0x%x,compressedSize:0x%x,ExtraFieldLength:0x%x,FileNameLength:0x%x",
                 ziphead->frUncompressedSize,ziphead->frCompressedSize,ziphead->frExtraFieldLength,ziphead->frFileNameLength);


            offset_start = offset+count+ziphead->frExtraFieldLength+ziphead->frFileNameLength;
            offset_end = offset_start + ziphead->frCompressedSize;

            LOGD("[AssetBundleDecryptor::InitZIPfileInfo] init success !\n offset_start %d ,offset_end %d",offset_start,offset_end);

        }
        lseek(fd, off, SEEK_SET);

        if(filename!=NULL)
            free(filename);

    }else{
        LOGD("[AssetBundleDecryptor::InitZIPfileInfo] is not ziphead");
        return 0;
    }

    return 1;

}

/* inflate 调用很频繁，打log会严重影响加载速度
 */
HOOK_DEF(int,inflate,z_streamp strm, int flush){

    void *input = strm->next_in;
    Bytef *output = strm->next_out;
    u_long outlen = strm->avail_out;

    int ret = orig_inflate(strm,flush);

    outlen = outlen - strm->avail_out;

    if(input>=readbuf&&input<=((int *)readbuf+now_count )){

        if(readbuf == input){

			if(strstr((char *)output,"AAAAAAA") != NULL){

                    //解密
                    }

                    return ret;
            }
        }
//                LOGD("[inflate - before ] output [%p][%p] 0x%x,0x%x，0x%x，0x%x total_out 0x%x, outlen %d %d"
//                        ,output,strm->next_out,output[0],output[1],output[2],output[3],strm->total_out,outlen,strm->avail_out);
        int num = strm->total_out - outlen -7;

        //len =  1024 时是偏移，修改内容不影响加载,为了节省时间不解密
        if(outlen == 1024)
            return ret;

        for(int i = 0; i<outlen;i++){
            output[i] = output[i] ^ key[(num +i)%10];
//          LOGD("[inflate] key[%d] 0x%x,output[%d] 0x%x",(num +i)%10,key[(num +i)%10],i,output[i]);
         }
    }
    return ret;
}

void AssetBundleDecryptor::registerHook() {

    LOGD("in registerHook  pid %d",getpid());

    std::string libpath = get_libpath();
    libpath.append("libunity.so");

    LOGD("libunity : %s",libpath.data());

    void *handle = dlopen(libpath.data(),RTLD_LAZY);

    xhook_register(libpath.data(),"inflate",(void*)new_inflate,(void **)&orig_inflate);

    xhook_register("libc.so","read",(void*)new_read,(void **)&orig_read);
//    //关于 加载 ab 包 不在unity.so 里

}

```

