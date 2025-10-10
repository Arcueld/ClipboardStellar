# 总结及效果

1.   获取cbdhsvc所在svchost的pid
2.   openprocess 然后 枚举其中的模块 找到`windows.applicationmodel.datatransfer.dll`
3.   获取CUnicodeTextFormat vtable地址
4.   扫整个已提交的私有内存 RW权限, 解析结构

![image-20251008211216667](https://img-host-arcueid.oss-cn-hangzhou.aliyuncs.com/img202510101540122.png)