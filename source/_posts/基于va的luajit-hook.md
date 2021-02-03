---
title: 基于va的luajit hook
date: 2020-07-03 11:53:55
tags: tools
---

## hook时机

根据  [jithook](https://www.anquanke.com/post/id/86958)中介绍，luaopen_jit 是 最后一个加载的库 [lua lib_init.c](https://github.com/LuaDist/luajit/blob/master/src/lib_init.c#L18-L30)

所以选择在 hook luaopen_jit 来加载hook.lua

```C
static const luaL_Reg lj_lib_load[] = {
  { "",			luaopen_base },
  { LUA_LOADLIBNAME,	luaopen_package },
  { LUA_TABLIBNAME,	luaopen_table },
  { LUA_IOLIBNAME,	luaopen_io },
  { LUA_OSLIBNAME,	luaopen_os },
  { LUA_STRLIBNAME,	luaopen_string },
  { LUA_MATHLIBNAME,	luaopen_math },
  { LUA_DBLIBNAME,	luaopen_debug },
  { LUA_BITLIBNAME,	luaopen_bit },
  { LUA_JITLIBNAME,	luaopen_jit },
  { NULL,		NULL }
};

static const luaL_Reg lj_lib_preload[] = {
#if LJ_HASFFI
  { LUA_FFILIBNAME,	luaopen_ffi },
#endif
  { NULL,		NULL }
};

LUALIB_API void luaL_openlibs(lua_State *L)
{
  const luaL_Reg *lib;
  for (lib = lj_lib_load; lib->func; lib++) {
    lua_pushcfunction(L, lib->func);//将一个 C 函数压入堆栈。 这个函数接收一个 C 函数指针，并将一个类型为 function 的 Lua 值 压入堆栈。当这个栈定的值被调用时，将触发对应的 C 函数。(其实就是注册函数，不过传入的函数还是要遵循lua_CFunction的那个规则，此处不重要)
    lua_pushstring(L, lib->func);//同理，把指针lib->name指向的以零结尾的字符串压栈
    lua_call(L, 1, 0);//执行 lib->func（lib->func），相似的还有个pcall，多了个返回错误

  }
  luaL_findtable(L, LUA_REGISTRYINDEX, "_PRELOAD",
		 sizeof(lj_lib_preload)/sizeof(lj_lib_preload[0])-1);
  for (lib = lj_lib_preload; lib->func; lib++) {
    lua_pushcfunction(L, lib->func);
    lua_setfield(L, -2, lib->name);
  }
  lua_pop(L, 1);
}

/*lua_call
要调用一个函数请遵循以下协议：首先，要调用的函数应该被压入栈；接着，把需要传递给这个函数的参数按正序压栈； 这是指第一个参数首先压栈。最后调用一下 lua_call；nargs 是你压入栈的参数个数。 当函数调用完毕后，所有的参数以及函数本身都会出栈。 而函数的返回值这时则被压栈。 返回值的个数将被调整为 nresults 个，除非 nresults 被设置成 LUA_MULTRET。 在这种情况下，所有的返回值都被压入堆栈中。 Lua 会保证返回值都放入栈空间中。 函数返回值将按正序压栈（第一个返回值首先压栈）， 因此在调用结束后，最后一个返回值将被放在栈顶。
*/
```

<!-- more -->

### 实现

当VA加载libtolua.so的时候，找到函数luaopen_jit，jit加载完毕后，加载/sdcard/mydump/hook.lua并执行。

```c
    if (strstr(name, "libtolua.so") != NULL && Count != true) {

        MYLOGD("onSoLoaded==>%s", name);
        void *xluaL_loadbuffer = (void *) dlsym(handle, "luaL_loadbuffer");
        MYLOGD("onSoLoaded=> xluaL_loadbuffer:%p", xluaL_loadbuffer);
        if (xluaL_loadbuffer != NULL) {
            MSHookFunction((void *) xluaL_loadbuffer, (void *) new_luaL_loadbuffer,
                           (void **) &old_luaL_loadbuffer);
            Count = true;
        }
        void* luaopen_jit = dlsym(handle,"luaopen_jit");

        _lua_pcall = (int(*)(lua_State *L, int nargs, int nresults, int errfunc))dlsym(handle,"lua_pcall");

        _luaL_loadfilex = (int(*)(lua_State *L, const char *filename, const char *mode))dlsym(handle,"luaL_loadfilex");

        MSHookFunction((void *) luaopen_jit, (void *) new_luaopen_jit,(void **) &old_luaopen_jit);

    }




int new_luaopen_jit(lua_State *L)
{
    MYLOGD("luajit luaopen call");
    int ret_val = old_luaopen_jit(L);
    if(!has_load_jithook){
        _luaL_loadfilex(L, "/sdcard/mydump/hook.lua", NULL) || _lua_pcall(L, 0, -1, 0);
        //int luaL_loadfilex (lua_State *L, const char *filename,const char *mode);
        //lua_pcall (lua_State *L, int nargs, int nresults, int errfunc);
        has_load_jithook = true;
    }

    return ret_val;
}
```

### hook.lua



使用lua 自带的debug库，[详细介绍](http://lua-users.org/wiki/DebugLibraryTutorial)

大体作用就是 每次调用某个函数会检查函数名或者其他信息是否可疑，将可疑函数的相关的局部变量保存到文件里。找到参数时用相应函数修改。

```lua
function serialize(obj)  
    local lua = ""  
    local t = type(obj)  
    if t == "number" then  
        lua = lua .. obj  
    elseif t == "boolean" then  
        lua = lua .. tostring(obj)
    elseif t == "userdata" then  
    	lua = lua .. "userdata:{\n"  
    	-- if udata ~= nil then
    	-- 	for k, v in pairs(udata) do  
	    --    lua = lua .. "[" .. serialize(k) .. "]=" .. serialize(v) .. ",\n"
	    --     end
	    -- end  
	    lua = lua .. "}"
  
    elseif t == "function" then  
        lua = lua .. "function"  
    elseif t == "string" then  
        lua = lua .. obj
    elseif t == "table" then  

    	-- if obj then
    	-- 	lua = lua .. luaJson.table2json(obj)
    	-- else
    	-- 	lua = lua .. "[empty table]"
    	-- end
    	
        lua = lua .. "{\n"  
	    for k, v in pairs(obj) do  
	        lua = lua .. "[" .. serialize(k) .. "]=" .. serialize(v) .. ",\n"  
	    end  

        lua = lua .. "}"  
    elseif t == "nil" then  
        return nil  
    else  
        return "can not serialize a " .. t .. " type." 
    end  
    return lua  

end



function trace(event, line)
    local info = debug.getinfo(2)
    -- debug.getinfo ([thread,] f [, what])
    -- f 表示运行在指定线程的调用栈对应层次上的函数
    -- what 描述需要返回的内容，不指定就返回全部

    if not info then return end
    if not info.name then return end
    if string.len(info.name) <= 1 then return end


   -- if string.find(info.name,"printJson") == nil  and         	 string.find(info.name,"callEx") == nil then
   -- 		return
   -- end
   if string.find(info.name,"Surrender") == nil  and string.find(info.name,"callEx") == nil then
   		return
   end
 	-- if info.what == "C" then
 	-- 	return
 	-- end

    local traceFile = io.open("/sdcard/mydump/luajit_log.txt", "a")

    local i = 1
    traceFile:write("\n\n"..info.short_src .. ":".. info.name .. "()\n")

	-- local func = debug.getinfo(2).func
	-- traceFile:write("\n----------------[upval]----------------\n")
	-- repeat
	--     name, val = debug.getupvalue(info.func, i)
	--     if name then
	--         traceFile:write("[index] :" .. i .."\n[" ..  serialize(name) .. "]:".. serialize(val) .. "\n")    -- 依次输出两个"upvalues"的名字和值。
	--     end
	--     i = i+1
	-- until not name


	traceFile:write("\n----------------[local]----------------\n")
	hookcount = 1;
    a = 1
	while true do
        local name, value = debug.getlocal(2, a)
        -- debug.getlocal ([thread,] f, local)
        -- 此函数返回在栈的 f 层处函数的索引为 local 的局部变量的名字和值。这个函数不仅用于访问显式定义的局部变量，也包括形参、临时变量等
        if not name then break end
        if not value then break end
        -- print(name, value)
        if type(value) == "string" then

        	if string.find(value,"buy") ~= nil then

        	hookcount = a + 1;
        	end
        end

        traceFile:write(name .. ": " .. serialize(value)  .. "\n")
        a = a + 1
    end

   --  if hookcount ~= 1 then
   --      	val = {
			-- 	["shelfid"]=31003,
			-- 	["costType"]=111,
			-- 	["num"]=100,
			-- 	["price"]=25,
			-- }
   --      	debug.setlocal(2,hookcount,val)
   --  end

	traceFile:write(name .. ": " .. value .. "\n")
	traceFile:write("\n----------------".. info.name.. "----------------\n")
	traceFile:flush()
	traceFile:close()

end

debug.sethook(trace, "c")
-- 每调用一个lua函数的时候会触发trace
-- debug.sethook ([thread,] hook, mask [, count])
-- 当调用一个lua函数的时候，会触发call事件 "c"
-- 当函数返回的时候，会触发一个return事件  "r"
-- 当执行下一行代码的时候，会触发一个line事件 "l"
 
```



### 问题

对于local  value 的解析，游戏里个别地方 数据结构复杂，会table嵌套table、userdata。

（userdata 是一种用户自定义数据，用于表示一种由应用程序或 C/C++ 语言库所创建的类型，可以将任意 C/C++ 的任意数据类型的数据（通常是 struct 和 指针）存储到 Lua 变量中调用）

`debug.getuservalue (u)` 这个是把userdata转换成table

Returns the Lua value associated to `u`. If `u` is not a userdata, returns **nil**.

网上常见的两种解析方法都不可行：

 递归解析（emm）https://www.jianshu.com/p/9b388de0899b

可解析userdata，但是数据过于复杂，lua报错无限递归栈溢出

json编码

可解析复杂的table，但是，json库、cjson库，网友实现的其他json库都不能解析userdata