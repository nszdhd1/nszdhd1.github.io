---
title: magisk-riru 使用
date: 2020-04-07 17:51:27
tags: tools
---

###  1. riru-core  riru框架实现原理

riru框架入口是 riru-core/jni/main/main.cpp中的函数constructor().

```c++
extern "C" void constructor() __attribute__((constructor));

void constructor() {
    static int loaded = 0;
    if (loaded)
        return; // 如果已经加载就退出，保证只加载一次

    loaded = 1;

    if (getuid() != 0) //不是root用户就退出
        return;

    char cmdline[ARG_MAX + 1];
    get_self_cmdline(cmdline);

    if (!strstr(cmdline, "--zygote"))
        return;

    LOGI("Riru %s in %s", VERSION_NAME, ZYGOTE_NAME);

    LOGI("config dir is %s", get_config_dir());

    char path[PATH_MAX];
    snprintf(path, PATH_MAX, "%s/.disable", get_config_dir());

    if (access(path, F_OK) == 0) {
        LOGI("%s exists, do nothing.", path); // 判断该框架是否停用，停用了就退出
        return;
    }

    read_prop();
    //使用了 iqiyi 的 xhook ，有兴趣可以去github上看。https://github.com/iqiyi/xhook
    XHOOK_REGISTER(".*\\libandroid_runtime.so$", jniRegisterNativeMethods);

    if (xhook_refresh(0) == 0) {
        xhook_clear();
        LOGI("hook installed");
    } else {
        LOGE("failed to refresh hook");
    }

    load_modules();
}
```

<!-- more -->

上面这段代码主要是进行一些判断，并且hook 库libandroid_runtime.so中的jniRegisterNativeMethods函数。

```c++
/**
 *  将系统属性
 *  ro.build.version.sdk
 *  ro.build.version.preview_sdk
 *  ro.build.version.release
 *  保存到全局变量中
 * */
static void read_prop() {
    char sdk[PROP_VALUE_MAX + 1];
    if (__system_property_get("ro.build.version.sdk", sdk) > 0)
        sdkLevel = atoi(sdk);

    if (__system_property_get("ro.build.version.preview_sdk", sdk) > 0)
        previewSdkLevel = atoi(sdk);

    __system_property_get("ro.build.version.release", androidVersionName);

    LOGI("system version %s (api %d, preview_sdk %d)", androidVersionName, sdkLevel,
         previewSdkLevel);
}
```



```c++
#define XHOOK_REGISTER(PATH_REGEX, NAME) \
    if (xhook_register(PATH_REGEX, #NAME, (void*) new_##NAME, (void **) &old_##NAME) != 0) \
        LOGE("failed to register hook " #NAME "."); \

#define NEW_FUNC_DEF(ret, func, ...) \
    static ret (*old_##func)(__VA_ARGS__); \
    static ret new_##func(__VA_ARGS__)

NEW_FUNC_DEF(int, jniRegisterNativeMethods, JNIEnv *env, const char *className,
             const JNINativeMethod *methods, int numMethods) {
    put_native_method(className, methods, numMethods);

    LOGV("jniRegisterNativeMethods %s", className);

    JNINativeMethod *newMethods = nullptr;
    if (strcmp("com/android/internal/os/Zygote", className) == 0) {
        newMethods = onRegisterZygote(env, className, methods, numMethods);
    } else if (strcmp("android/os/SystemProperties", className) == 0) {
        // hook android.os.SystemProperties#native_set to prevent a critical problem on Android 9
        // see comment of SystemProperties_set in jni_native_method.cpp for detail
        newMethods = onRegisterSystemProperties(env, className, methods, numMethods);
    }

    int res = old_jniRegisterNativeMethods(env, className, newMethods ? newMethods : methods,
                                           numMethods);
    /*if (!newMethods) {
        NativeMethod::jniRegisterNativeMethodsPost(env, className, methods, numMethods);
    }*/
    delete newMethods;
    return res;
}
```

根据宏定义XHOOK_REGISTER 可知，关键函数在 new_jniRegisterNativeMethods，而old_func 、new_fun都在NEW_FUNC_DEF处定义了。根据代码，关键函数是onRegisterZygote、onRegisterSystemProperties。

```c++
//onRegisterZygote 关键函数：
if (newMethods[i].fnPtr != methods[i].fnPtr) {
                LOGI("replaced com.android.internal.os.Zygote#nativeSpecializeAppProcess");//其实重点已经被log打印出来了
                riru_set_native_method_func(MODULE_NAME_CORE, className, newMethods[i].name,
                                            newMethods[i].signature, newMethods[i].fnPtr);

                //replaced += 1;
            }
            
if (newMethods[i].fnPtr != methods[i].fnPtr) {
                LOGI("replaced com.android.internal.os.Zygote#nativeForkAndSpecialize");
                riru_set_native_method_func(MODULE_NAME_CORE, className, newMethods[i].name,
                                            newMethods[i].signature, newMethods[i].fnPtr);

                replaced += 1;
            }
if (newMethods[i].fnPtr != methods[i].fnPtr) {
                LOGI("replaced com.android.internal.os.Zygote#nativeForkAndSpecialize");
                riru_set_native_method_func(MODULE_NAME_CORE, className, newMethods[i].name,
                                            newMethods[i].signature, newMethods[i].fnPtr);

                replaced += 1;
            }

//onRegisterSystemProperties中
if (newMethods[i].fnPtr != methods[i].fnPtr) {
                LOGI("replaced android.os.SystemProperties#native_set");

                riru_set_native_method_func(MODULE_NAME_CORE, className, newMethods[i].name,
                                            newMethods[i].signature, newMethods[i].fnPtr);
            }


void riru_set_func(const char *module_name, const char *name, void *func) EXPORT;
void riru_set_func(const char *module_name, const char *name, void *func) {
    unsigned long index = get_module_index(module_name);
    if (index == 0)
        return;

    //LOGV("set_func %s %s %p", module_name, name, func);

    auto module = get_modules()->at(index - 1);
    (*module->funcs)[name] = func;
}

void riru_set_native_method_func(const char *module_name, const char *className, const char *name,
                                 const char *signature, void *func) {
    riru_set_func(module_name, (std::string(className) + name + signature).c_str(), func);
}
}

 
```

上面代码主要的作用是将nativeSpecializeAppProcess、nativeForkAndSpecialize、nativeForkAndSpecialize等函数替换并且导出，方便我们写新模块时使用。

最后一步是load_modules()，也就是加载我们写的riru模块：



```c++
static void load_modules() {
    DIR *dir;
    struct dirent *entry;
    char path[PATH_MAX], modules_path[PATH_MAX], module_prop[PATH_MAX], api[PATH_MAX];
    int moduleApiVersion;
    void *handle;

    snprintf(modules_path, PATH_MAX, "%s/modules", get_config_dir());

    if (!(dir = _opendir(modules_path)))//这里是读取magisk已经安装的模块
        return;

    while ((entry = _readdir(dir))) {
        if (entry->d_type == DT_DIR) {
            if (entry->d_name[0] == '.')
                continue;

            snprintf(path, PATH_MAX, MODULE_PATH_FMT, entry->d_name);

            if (access(path, F_OK) != 0) {
                PLOGE("access %s", path);
                continue;
            }

            snprintf(module_prop, PATH_MAX, "%s/%s/module.prop", modules_path, entry->d_name);//一些读取模块的配置信息操作
            if (access(module_prop, F_OK) != 0) {
                PLOGE("access %s", module_prop);
                continue;
            }

            moduleApiVersion = -1;
            if (get_prop(module_prop, "api", api) > 0) {
                moduleApiVersion = atoi(api);
            }

            if (isQ() && moduleApiVersion < 3) {
                LOGW("module %s does not support Android Q", entry->d_name);
                continue;
            }

            handle = dlopen(path, RTLD_NOW | RTLD_GLOBAL);
            if (!handle) {
                PLOGE("dlopen %s", path);
                continue;
            }
			//加载自己写的riru模块编译出来的so，并且将下面的函数加载进来替换原有的函数
            auto *module = new struct module(strdup(entry->d_name));
            module->handle = handle;
            module->onModuleLoaded = dlsym(handle, "onModuleLoaded");
            module->forkAndSpecializePre = dlsym(handle, "nativeForkAndSpecializePre");
            module->forkAndSpecializePost = dlsym(handle, "nativeForkAndSpecializePost");
            module->forkSystemServerPre = dlsym(handle, "nativeForkSystemServerPre");
            module->forkSystemServerPost = dlsym(handle, "nativeForkSystemServerPost");
            module->specializeAppProcessPre = dlsym(handle, "specializeAppProcessPre");
            module->specializeAppProcessPost = dlsym(handle, "specializeAppProcessPost");
            module->shouldSkipUid = dlsym(handle, "shouldSkipUid");
            get_modules()->push_back(module);

            if (moduleApiVersion == -1) {
                // only for api v2
                module->getApiVersion = dlsym(handle, "getApiVersion");

                if (module->getApiVersion) {
                    module->apiVersion = ((getApiVersion_t *) module->getApiVersion)();
                }
            } else {
                module->apiVersion = moduleApiVersion;
            }

            void *sym = dlsym(handle, "riru_set_module_name");
            if (sym)
                ((void (*)(const char *)) sym)(module->name);

            LOGI("module loaded: %s (api %d)", module->name, module->apiVersion);

            if (module->onModuleLoaded) {
                LOGV("%s: onModuleLoaded", module->name);

                ((loaded_t *) module->onModuleLoaded)();//执行自己模块的中onModuleLoaded
            }
        }
    }

    closedir(dir);
}
```

了解了riru框架的实现原理，就可以很好的使用riru写hook模块了。



### 2. riru-template  riru模块使用

模板 github地址：https://github.com/RikkaApps/Riru-ModuleTemplate

主要功能也是在main函数里。Riru-ModuleTemplate/module/src/main/cpp/main.cpp

riru模块相当原生态，很多东西都得你自己写，干啥都得开动自己的小脑筋，为了方便，可以先集成几个hook框架，got hook 我选了xhook，inline hook 用 Cydia substrate。

添加文件并且修改cmakelists（substrate编译arm64时有坑），成功后就可以开始使用了。



```c++
int ismyapp = 0;
#define PAGE_START(addr) ((addr) & PAGE_MASK)
#define PAGE_END(addr)   (PAGE_START(addr) + PAGE_SIZE)

extern "C" {
#define EXPORT __attribute__((visibility("default"))) __attribute__((used))
EXPORT void nativeForkAndSpecializePre(
        JNIEnv *env, jclass clazz, jint *_uid, jint *gid, jintArray *gids, jint *runtimeFlags,
        jobjectArray *rlimits, jint *mountExternal, jstring *seInfo, jstring *niceName,
        jintArray *fdsToClose, jintArray *fdsToIgnore, jboolean *is_child_zygote,
        jstring *instructionSet, jstring *appDataDir, jstring *packageName,
        jobjectArray *packagesForUID, jstring *sandboxId) {
    // packageName, packagesForUID, sandboxId are added from Android Q beta 2, removed from beta 5


    //packageName : forkAndSpecializePost
    // nicename is appname :com.xxx.xxx    appDataDir : /data/user/0/com.xxx.xxx
    const char *app_packageName = (env)->GetStringUTFChars(*appDataDir, 0);
    const char *app_niceName = (env)->GetStringUTFChars(*niceName, 0);
    //LOGD(" Riru hook  appname %s  niceName %s",app_packageName,app_niceName);

     if(strcmp(app_niceName,"com.xxx.xxx") ==0 ){
        ismyapp = 1;
     }else{
     ismyapp = 0;
     }
//此处用来判断是不是目标应用
}
    
    
 EXPORT int nativeForkAndSpecializePost(JNIEnv *env, jclass clazz, jint res) {
    if (res == 0) {
        // in app process
        if(ismyapp){//如果是目标应用
            int ret = -1;
            pthread_t tid1;
            ret = pthread_create(&tid1, NULL, reinterpret_cast<void *(*)(void *)>(thread_func1), NULL);//创建一个新线程thread_func1用来hook
            LOGD("create thread ret: %d\n", ret);

        }

    } else {
        // in zygote process, res is child pid
        // don't print log here, see https://github.com/RikkaApps/Riru/blob/77adfd6a4a6a81bfd20569c910bc4854f2f84f5e/riru-core/jni/main/jni_native_method.cpp#L55-L66
    }
    return 0;
}
    
void thread_func1() {

LOGD(" in Riru  testhook  thread_func1 ");
void *base_addr;
    while(true){

        base_addr = get_module_base(-1,"libxxx.so");
        LOGD("find libxxx.so %p", base_addr);
        if (base_addr != 0) {
                    break;
                }
    }//这一步是为了等待到目标so加载进内存

 void * symbol = lookup_symbol("/data/data/com.xxx.xxx/lib/libxxx.so","createxxx");
 MSHookFunction(symbol, (void*)&new_debug, (void**)&old_debug);
//inline hook 导出函数
   

int offset = 0x1234;
void * symboladdr =  base_addr + offset;
MSHookFunction(symboladdr, (void*)&new_debug, (void**)&old_debug);    
//可以hook so中全部函数    
 
mprotect((void *)PAGE_START(symboladdr), PAGE_SIZE, PROT_READ | PROT_WRITE);
 *(void **)symboladdr = new_debug;
  __builtin___clear_cache((void *)PAGE_START(addr), (void *)PAGE_END(addr));   

    
    
 int reg =xhook_register(".*/libxxx.so$", "createxxx", (void *) new_debug, (void **)(&old_debug));
 int ref = xhook_refresh(0);
 // xhook

 LOGD(" [cn.xxx.xxx] xhook_register %d  , xhook_refresh %d ",reg,ref);

}
    
 //获取进程加载模块的基址
void* get_module_base(pid_t pid, const char* module_name)
{
    FILE *fp;
    long addr = 0;
    char *pch;
    //保存模块的名称
    char filename[32];
    //保存读取的信息
    char line[1024];
    if (pid < 0)
    {
        //获取当前进程的模块的基址
        snprintf(filename, sizeof(filename), "/proc/self/maps");
    }
    else
    {
        //获取其他进程的模块的基址
        snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
    }
    //打开"/proc/pid/maps"文件
    fp = fopen(filename, "r");
    if (fp != NULL)
    {
        //循环读取"/proc/pid/maps"文件的信息，每次一行
        while (fgets(line, sizeof(line), fp))
        {
            //判断读取的信息line中是否包含要查找的模块名称
            if (strstr(line, module_name))
            {
                //以"-"为标记拆分字符串
                pch = strtok(line, "-");

                //字符串转无符号长整型的模块基址
                addr = strtoul(pch, NULL, 16 );

                //排除特殊情况
                if (addr == 0x8000)
                    addr = 0;

                break;
            }
        }
        fclose( fp );
    }
    //返回获取到的模块的基址
    return (void *)addr;
}
    
  //通过so库的绝对路径和函数名，找到其函数的映射地址
void* lookup_symbol(char* libraryname,char* symbolname)
{
    //获取so库的句柄
    void *handle = dlopen(libraryname, RTLD_GLOBAL | RTLD_NOW);
    if (handle != NULL){
        //根据so库句柄和符号名（即函数名）获取函数地址
        void * symbol = dlsym(handle, symbolname);
        if (symbol != NULL){
            return symbol;
        }else{
            LOGD("dl error: %s", dlerror());
            return NULL;
        }
    }else{
        return NULL;
    }
}
    
int (*old_debug)(int a1, const char *a2);
int new_debug(int a1, const char *a2){

        LOGD(" debug %s",a2);

        return old_debug(a1,a2);
    }    
```

到这里就可以开心的使用riru啦~

不过还是提醒大家一下，写模块需谨慎，乱写riru模块（比如我每次调用nativeForkAndSpecializePre都开启一个线程）是会导致手机无法开机的，尤其是刷不进TWRP的部分小米手机，刷机了解一下。

