# (VMDEasy)Virtual Machines Detect Easy
### 一款建议的可以帮助开发者快速检测实体机与虚拟机的工具

## 概述
此Python工具使用多种手段检测当前系统是否在虚拟机环境中运行。它结合了Windows系统特征分析、硬件检测和行为监控，提供基础的虚拟机识别能力。

[! WARNING]
>通过某些手段任然可以绕过虚拟机检测。

## 技术细节

### 1. 检测体系

| 检测类别 | 方法 | 描述 |
|----------|------|------|------|
| **基础特征** | 注册表扫描 | 检查系统产品名称和制造商信息 |
|  | 文件系统检测 | 查找虚拟机特有驱动文件 |
|  | 进程扫描 | 识别虚拟机服务进程 |
| **硬件特征** | CPU品牌分析 | 检测虚拟机特有的CPU标识 |
|  | 内存配置检测 | 分析内存大小是否典型虚拟机配置 |
|  | MAC地址检查 | 验证网卡MAC地址前缀 |
| **行为指标** | 时间漂移检测 | 测量sleep函数的执行偏差 |
|  | 指令延迟检测 | 监控系统调用执行时间 |
| **Hypervisor** | CPUID指令 | 检查ECX寄存器的Hypervisor位 |
|  | Hyper-V检测 | 分析systeminfo输出 |

### 2. 核心算法
*图表由DeepSeek-R1/V3生成*


### 3. 关键实现

#### CPUID指令读取
```python
class CPUID:
    def __call__(self, eax, ecx=0):
        if self._cpuid:
            regs = (ctypes.c_uint * 4)()
            self._cpuid(regs, eax, ecx)
            return [regs[0], regs[1], regs[2], regs[3]]
```

#### Hypervisor检测
```python
# 检查ECX寄存器的第31位 (0x80000000)
if ecx & (1 << 31):
    self._add_vm_signature(5)
```

#### 内存配置分析
```python
total_ram_gb = mem_status.ullTotalPhys / (1024 ** 3)
if total_ram_gb.is_integer():  # 虚拟机通常有整数内存配置
    self._add_vm_signature(1)
```

### 4. 检测权重系统

特征检测使用加权评分系统：
- 弱指标：权重1（如内存配置）
- 中等指标：权重2-3（如进程、文件检测）
- 强指标：权重4-5（如CPUID、CPU品牌）

最终置信度计算：
```
vm_confidence = (vm_signatures / total_signatures) * 100
```

## 使用方法

### 安装依赖
```bash
pip install pywin32 ctypes
```

### 运行程序
```bash
python main.py
```

### 运行结果
- 检测到虚拟机：显示"检测到正在虚拟机运行"
- 检测到物理机：显示"程序不在虚拟机环境运行"
- 结果通过Windows消息框显示

## 检测逻辑说明

### 严格模式
```python
if strict_mode and physical_signatures > 0:
    return False  # 物理机
```

### 置信度模式
```python
return vm_confidence > 80  # 80%阈值
```

[! IMPORTANT]
>## 注意事项
>
>1. 需要管理员权限访问注册表和系统文件
>2. 在Hyper-V环境中可能检测为物理机（设计预期）
>3. 部分检测可能被高级虚拟机绕过
>4. 内存检测仅适用于Windows系统

[! TIP]
>## 开发者说明
>
>该工具使用了以下Windows API：
>- `__cpuidex` (CPUID指令)
>- `GlobalMemoryStatusEx` (内存检测)
>- `GetSystemTime` (时间测量)

所有检测均在用户空间进行，不会修改系统设置或文件。

## 许可证

本项目采用 **GNU General Public License v3.0** (GPL-3.0) 许可证发布。

Copyright (C) 2025 HOE Software Team
