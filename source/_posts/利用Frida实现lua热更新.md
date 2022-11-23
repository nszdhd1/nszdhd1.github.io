---
title: 利用Frida实现lua热更新
date: 2022-03-21 15:32:47
tags: game
---

# 利用Frida实现lua热更新

## 背景与需求

对游戏进行修改时，尤其是代码逻辑在lua中，经常重启是一件很低效的事。所以考虑能不能有一款工具，**不需要重启游戏就能让lua文件改动后立刻生效**

非游戏开发，所以只有apk作为目标，无工程代码。

## 设计原理与实现

主要分为两个模块：

- **LuaFileWatcher**，检测lua文件发生变化，当发生变化时调用Hotfix.lua进行重载模块的操作。
- **Hotfix**，重载lua模块

### LuaFileWatcher

此处分享两种方法，一种使用Android的FileObserver（虽然本质上还是用的inotify），另一种直接使用 linux inotify。

<!-- more -->

#### android.os.FileObserver

关于该类的介绍，可以优先阅读：https://developer.android.com/reference/android/os/FileObserver

主要是通过frida js 实现 创建一个继承FileObserver的类，用于监控LUA_PATH下有哪些文件被打开了。

```js
const LUA_PATH = "文件监控路径"
Java.performNow(function (){
    var FileObserver = Java.use("android.os.FileObserver");
    var LuaFileObserver = Java.registerClass({
        name:'com.hotfix.LuaFileObserver',
        superClass:FileObserver,
        implements: [FileObserver],
        methods:{
            $init:[{
                returnType: 'void',
                arguments:['java.lang.String'],
                implementation:function (p){
                    this.$super.$init(p)
                }
            }, {
                    returnType: 'void',
                    arguments:[''],
                    implementation:function (){
                        this.$super.$init()
                    }
                }],
            $new:{
                returnType: 'void',
                arguments:['java.lang.String'],
                implementation:function (p){
                    this.$super.$new(p)
                }
            },
            stopWatching:{
                returnType: 'void',
                arguments:[''],
                implementation:function (){
                    this.$super.stopWatching()
                }
            },
            startWatching:{
                returnType: 'void',
                arguments:[''],
                implementation:function (){
                    this.$super.stopWatching()
                }
            },
            finalize:{
                returnType: 'void',
                arguments:[''],
                implementation:function (){
                    this.$super.stopWatching()
                }
            },
            onEvent:function(event,path){
               // console.log("event :"+event)
                //console.log("path :"+path)
            }

        }
    });
    var FileWatcher = LuaFileObserver.$new(LUA_PATH)
    FileObserver.onEvent.implementation = function (event,path){
        console.log("event :"+event)
        console.log("path :"+path)
        if(event == 32)
            doHotfix(path)
    }
    FileWatcher.startWatching()
})
```

优点：简单

缺点：不稳定，很多机型会提示ClassNotFound。

#### inotify

需要先了解inotify是什么，有什么用，怎么使用：https://man7.org/linux/man-pages/man7/inotify.7.html

该功能主要是创建一个线程，不停的监控LUA_PATH下文件打开的情况。如果有文件被打开，则加载一段lua代码。

```js
const LUA_PATH = "文件监控路径"
function LuaFileWatcher(){
    var inotify_init = new NativeFunction(Module.findExportByName(null,"inotify_init"),'int',[])
    var inotify_add_watch = new NativeFunction(Module.findExportByName(null,"inotify_add_watch"),'int',['int','pointer','int'])
    const read = new NativeFunction(Module.findExportByName(null,"read"),'int',['int','pointer','int']);
    var fd = inotify_init()
    var wd = inotify_add_watch(fd,Memory.allocUtf8String(LUA_PATH),256) //ALL_EVENTS = 4095,OPEN=32
    console.log("fd "+fd+",wd "+wd)
    const inotify_event_len = 0x10
    var data = Memory.alloc(inotify_event_len*10);
    while (1){
        let readlen = read(fd,data,inotify_event_len*10-1)
        if( readlen<0){
            console.log('[+] Unable to read  [!] ');
            continue
        }
        console.log(readlen,data)

        // struct inotify_event {
        //     __s32 wd;
        //     __u32 ;
        //     __u32 cookie;
        //     __u32 len;
        //     char name[0];
        // };
        for (let i = 0; i < (readlen/0x10) ; i++) {
            let readData = data.add(i*0x10)
            let envent = []
            envent.wd = readData.readS32();
            envent.mask = readData.add(4).readU32();
            envent.cookie = readData.add(8).readU32();
            envent.len = readData.add(12).readU32();
            envent.name = readData.add(16).readCString();
            console.log('open file : ',envent.name,envent.mask)
            if(envent.mask!=256)
                continue;
            try{
                console.log('----------------------')
                let luaname = envent.name.replaceAll("_",".")
                console.log("luaname"+luaname)
                var scr ='if string.find(package.path,\"'+ LUA_PATH+'\") == nil then\n' +
                    '    package.path = package.path .. \";'+LUA_PATH+'/?\"\n' +
                    'end\n'+
                    'require(\"HotFixOOOK\")\n'+
                    'hotfix(\"'+luaname+'\")'
                var luaL_loadstring_ret = luaL_loadstring(lua_State,Memory.allocUtf8String(scr))
                console.log("luaL_loadstring_ret  : "+luaL_loadstring_ret)
                send("load lua init ret "+ lua_pcall(lua_State,0,0,0) + "  str:"+lua_tolstring(lua_State, -1).readCString())

            }catch (e) {
                send("err:"+e.toString())
            }
        }

    }

}

var  pthread_create = new NativeFunction(Module.findExportByName(null,"pthread_create"),'int',['pointer','pointer','pointer','pointer'])
var LuaFileWatcherNative = new NativeCallback(LuaFileWatcher,'void',['void'])

//启动新线程对目标目录进行文件监控。
pthread_create(Memory.alloc(16),new NativePointer(0),LuaFileWatcherNative,new NativePointer(0))
```

 package.path = package.path .. ";LUA_PATH/?",这句的主要作用是将LUA_PATH添加到luaenv加载路径里面。不加会require不到用于热更的lua代码HotFixOOOK。

**lua_State** 通过hook libxlua.so的luaL_openlibs函数获取。

### Hotfix

根据[LuaRuntimeHotfix](https://github.com/756915370/LuaRuntimeHotfix)中的热更代码修改了一下。（默认apk使用的是xlua，如果不是xlua，删掉打印日志即可）

```lua
function hotfix(filename)
    CS.UnityEngine.Debug.LogError("start hotfix: "..filename)
    local dumpname = string.gsub(filename,"%.","_")

    local oldModule
    if package.loaded[filename] then
        oldModule = package.loaded[filename]
    elseif package.loaded[dumpname] then
        oldModule = package.loaded[dumpname]
    else
        CS.UnityEngine.Debug.LogError('this file nevev loaded: '..filename)
        require(filename)
    end

    package.loaded[filename] = nil
    package.loaded[dumpname] = nil

    CS.UnityEngine.Debug.LogError('loaded newMpdule '..dumpname..' ,oldModule: '..filename)
    local newModule = package.loaded[dumpname]
    if newModule == nil then
        -- try again
        require(dumpname)
        newModule = package.loaded[dumpname]
    end

    CS.UnityEngine.Debug.LogError('oldModule: '.. tostring(oldModule)..' ,newModule: '..tostring(newModule))
    -- 注释掉就只能修改函数
    update_table(newModule, oldModule,updated_tables)

    if newModule == nil then
        package.loaded[filename] = oldModule
        CS.UnityEngine.Debug.LogError('replaced faild !! ')
        return
    end
    package.loaded[filename] = newModule

    CS.UnityEngine.Debug.LogError('replaced succeed')

end
function update_func(new_func, old_func)
    assert("function" == type(new_func))
    assert("function" == type(old_func))

    -- Get upvalues of old function.
    local old_upvalue_map = {}
    local OldExistName = {}
    for i = 1, math.huge do
        local name, value = debug.getupvalue(old_func, i)
        if not name then break end
        old_upvalue_map[name] = value
        OldExistName[name] = true
    end

    -- Update new upvalues with old.
    for i = 1, math.huge do
        local name, value = debug.getupvalue(new_func, i)
        if not name then break end
        --CS.UnityEngine.Debug.LogError('set up value: name:'..name..' typeof '.. type(value))
        if OldExistName[name] then
            local old_value = old_upvalue_map[name]
            if type(old_value) == "function" then
                setfenv(new_func, getfenv(old_func))
                debug.setupvalue(new_func, i, old_value)
            else
                debug.setupvalue(new_func, i, old_value)
            end
        else
             -- 对新添加的upvalue设置正确的环境表
            ResetENV(value,name)
        end
    end
end

function update_table(new_table, old_table, updated_tables)
    assert("table" == type(new_table))
    assert("table" == type(old_table))

    -- Compare 2 tables, and update old table.
    for key, value in pairs(new_table) do
        local old_value = old_table[key]
        local type_value = type(value)
        if type_value == "function" then
            update_func(value, old_value)
            old_table[key] = value

        elseif type_value == "table" then
            if ( updated_tables[value] == nil ) then
                updated_tables[value] = true
                update_table(value, old_value,updated_tables)
            end
        end
    end

    ---- Update metatable.
    local old_meta = debug.getmetatable(old_table)
    local new_meta = debug.getmetatable(new_table)
    if type(old_meta) == "table" and type(new_meta) == "table" then
        update_table(new_meta, old_meta,updated_tables)
    end
end
```

#### 参考

游戏开发视角实现的lua热更：[LuaRuntimeHotfix](https://github.com/756915370/LuaRuntimeHotfix)

