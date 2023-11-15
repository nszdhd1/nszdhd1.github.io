---
title: ctfLuaOpcode还原writeup
date: 2023-11-15 14:55:14
tags: Analytics
---

主要考察opcode还原，具体可参考：[[原创]用 Lua 简单还原 OpCode 顺序](https://bbs.kanxue.com/thread-250618.htm)。但是中国女人一身反骨，就想硬刚逆向。通过libjava.so可知lua版本是5.3.3

  ![img](image/ctfLuaOpcode还原writeup/1213213.png) 除了众所周知的luaV_execute以外，还可以通过其他地方比如funcnamefromcode进行分析。

<!-- more -->

 ![img](image/ctfLuaOpcode还原writeup/dasdaeqt.png)

 可通过搜索"for iterator"字符串，找到函数地址，并使用ida查看伪代码，虽然顺序可能会由轻微变动，但case 的数量是不会变的，所以可以知道OP_ADD = 0xe,到op_shr=0x19,与源opcode只相差1，所以只要知道是哪个指令被从后挪到前就行了。

 ![img](image/ctfLuaOpcode还原writeup/113123123.png)

 通过查找源码：可以知道TMS的值（先默认为没修改）可知 0为CONCAT，9为SETTABUP，0xb为SETTABLE，以此类推即可获得opcode

 ![img](image/ctfLuaOpcode还原writeup/33265701.png)

下载unluac，将如下代码添加到opcodemap：



```java
  else if(version == 0x53){
      map = new Op[47];
      map[0x1] = Op.MOVE;
      map[2] = Op.LOADK;
      map[0x3] = Op.LOADKX;
      map[4] = Op.LOADBOOL;
      map[5] = Op.LOADNIL;
      map[0x6] = Op.GETUPVAL;
      map[0x7] = Op.GETTABUP;
      map[8] = Op.GETTABLE;
      map[0x9] = Op.SETTABUP;
      map[0xa] = Op.SETUPVAL;
      map[0xb] = Op.SETTABLE;
      map[0xc] = Op.NEWTABLE;
      map[0xd] = Op.SELF;
      map[0xe] = Op.ADD;
      map[0xf] = Op.SUB;
      map[0x10] = Op.MUL;
      map[0x11] = Op.MOD;
      map[0x12] = Op.POW;
      map[0x13] = Op.DIV;
      map[0x14] = Op.IDIV;
      map[0x15] = Op.BAND;
      map[0x16] = Op.BOR;
      map[0x17] = Op.BXOR;
      map[0x18] = Op.SHL;
      map[0x19] = Op.SHR;
      map[0x1a] = Op.UNM;
      map[0x1B] = Op.BNOT;
      map[0x1c] = Op.NOT;
      map[0x1d] = Op.LEN;
      map[0x0] = Op.CONCAT;
      map[30] = Op.JMP;
      map[31] = Op.EQ;
      map[32] = Op.LT;
      map[33] = Op.LE;
      map[34] = Op.TEST;
      map[35] = Op.TESTSET;
      map[36] = Op.CALL;
      map[37] = Op.TAILCALL;
      map[38] = Op.RETURN;
      map[39] = Op.FORLOOP;
      map[40] = Op.FORPREP;
      map[0x29] = Op.TFORCALL;
      map[42] = Op.TFORLOOP;
      map[43] = Op.SETLIST;
      map[44] = Op.CLOSURE;
      map[45] = Op.VARARG;
      map[46] = Op.EXTRAARG;
}
```

 获取到结果为：

```lua
function Xor(num1, num2)
  local tmp1 = num1
  local tmp2 = num2
  local str = ""
  repeat
    local s1 = tmp1 % 2
    local s2 = tmp2 % 2
    if s1 == s2 then
      str = "0" .. str
    else
      str = "1" .. str
    end
    tmp1 = math.modf(tmp1 / 2)
    tmp2 = math.modf(tmp2 / 2)
  until tmp1 == 0 and tmp2 == 0
  return tonumber(str, 2)
end
function encrypt(script)
  local key_byte = 5
  local len = string.len(script)
  local result = ""
  for i = 1, len do
    local byte = string.byte(script, i)
    local result_byte = Xor(byte, key_byte) + 1
    result = result .. string.char(result_byte)
  end
  return result
end
```

```python
def XorRestore(xor_result, num):
    xor_result_bin = bin(xor_result)[2:]  # 将异或结果转换为二进制表示，并去掉前缀 '0b'
    num_bin = bin(num)[2:]  # 将原始数转换为二进制表示，并去掉前缀 '0b'

    # 确保两个二进制字符串的长度一致
    max_len = max(len(xor_result_bin), len(num_bin))
    xor_result_bin = xor_result_bin.zfill(max_len)
    num_bin = num_bin.zfill(max_len)

    restored_str = ""
    for i in range(max_len):
        if xor_result_bin[i] == num_bin[i]:
            restored_str += "0"
        else:
            restored_str += "1"

    return int(restored_str, 2)
s = ''
for i in 'blue-army-kd':
    result_byte = ord(i) - 1
    ori_byte = XorRestore(result_byte,5)
    s += chr(ori_byte)
print(s)#dnqa)eti})of
print(hashlib.md5(s.encode()).hexdigest())#915d2431f984d55f331403c4a37ca0f7
```

 apk输入dnqa)eti})of即可获取flag

 ![img](image/ctfLuaOpcode还原writeup/33358997.png)

frida js 赛后考虑到方便其他人复现，可以使用以下脚本:

```js
var targets = []
Thread.sleep(1)
while (targets.length == 0){
    targets = Process.enumerateModules().filter(mod => mod.name.indexOf("lua") != -1)
    // if(Process.findModuleByName("libluajava.so")!= null)
    //     targets[0] = Process.findModuleByName("libluajava.so");
    send("find lua lib , wait ...")
}
send(targets)

function run(targets) {
    targets.forEach((target)=>{
        console.log(target.findExportByName('luaL_loadstring'))
        // lua_State *luaL_newstate (void);
        var luaL_newstate = new NativeFunction(target.findExportByName('luaL_newstate'),'pointer',[]);
        // int luaL_loadbuffer (lua_State *L, const char *buff, size_t sz, const char *name);
        // var luaL_loadbuffer = new NativeFunction(target.findExportByName('luaL_loadbuffer'),'int',['pointer','pointer','int','pointer']);
        //int lua_pcall (lua_State *L, int nargs, int nresults, int errfunc);
        var lua_pcallk = new NativeFunction(target.findExportByName('lua_pcallk'),'int',['pointer','int','int','int','int','int'])
        var luaL_loadstring = new NativeFunction(target.findExportByName("luaL_loadstring"),'int',['pointer','pointer'])
        var lua_tolstring = new NativeFunction(target.findExportByName("lua_tolstring"),'pointer',['pointer','int'])
        var luaL_openlibs = new NativeFunction(target.findExportByName('luaL_openlibs'),'void',['pointer']);
        var lua_State = luaL_newstate();

        console.log("luaL_openlibs:"+luaL_openlibs(lua_State))

//
        var scr= 'function enco()\n' +
            '    -- ...略\n' +
            '    print("mytest")\n' +
            '\tprint(type(print)) \n' +
            '\ttab1 = { key1 = "val1", key2 = "val2", "val3" }\n' +
            '\tfor k, v in pairs(tab1) do\n' +
            '\t\tprint(k .. " - " .. v)\n' +
            '\tend\n' +
            '\tc = 5           -- 全局变量\n' +
            '    local d = 6 \n' +
            '\ta = 21\n' +
            '\tb = 10\n' +
            '\tq = a + b\n' +
            '\tlocal myArray = {10, 20, 30, 40, 50}\n' +
            '\tarray = {}\n' +
            '\tfor i=1,3 do\n' +
            '\t   array[i] = {}\n' +
            '\t\t  for j=1,3 do\n' +
            '\t\t\t array[i][j] = i*j\n' +
            '\t\t  end\n' +
            '\tend\n' +
            'end\n' +
            'local data = string.dump(enco)\n' +
            'local fp = io.open("data/data/cc.chenhe.lib.androidlua.demo/enco.luac","w")\n' +
            'fp:write(data)\n' +
            'fp:close()\n'

        // console.log(scr)

        var luaL_loadstring_ret = luaL_loadstring(lua_State,Memory.allocUtf8String(scr))
        console.log("luaL_loadstring_ret  : "+luaL_loadstring_ret)
        if(luaL_loadstring_ret == 0)
            console.log("load lua ini  t ret "+ lua_pcallk(lua_State,0,-1,0,0,0) + "  str  :"+lua_tolstring(lua_State, -1).readCString())

    })

}
console.log(targets[0].name)
run(targets)
```

