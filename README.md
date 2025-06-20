# (VMDEasy)Virtual Machines Detect Easy
### һ���Ŀ��԰��������߿��ټ��ʵ�����������Ĺ���

## ����
��Python����ʹ�ö����ֶμ�⵱ǰϵͳ�Ƿ�����������������С��������Windowsϵͳ����������Ӳ��������Ϊ��أ��ṩ�����������ʶ��������

[! WARNING]
>ͨ��ĳЩ�ֶ���Ȼ�����ƹ��������⡣

## ����ϸ��

### 1. �����ϵ

| ������ | ���� | ���� |
|----------|------|------|------|
| **��������** | ע���ɨ�� | ���ϵͳ��Ʒ���ƺ���������Ϣ |
|  | �ļ�ϵͳ��� | ������������������ļ� |
|  | ����ɨ�� | ʶ�������������� |
| **Ӳ������** | CPUƷ�Ʒ��� | �����������е�CPU��ʶ |
|  | �ڴ����ü�� | �����ڴ��С�Ƿ������������� |
|  | MAC��ַ��� | ��֤����MAC��ַǰ׺ |
| **��Ϊָ��** | ʱ��Ư�Ƽ�� | ����sleep������ִ��ƫ�� |
|  | ָ���ӳټ�� | ���ϵͳ����ִ��ʱ�� |
| **Hypervisor** | CPUIDָ�� | ���ECX�Ĵ�����Hypervisorλ |
|  | Hyper-V��� | ����systeminfo��� |

### 2. �����㷨
*ͼ����DeepSeek-R1/V3����*


### 3. �ؼ�ʵ��

#### CPUIDָ���ȡ
```python
class CPUID:
    def __call__(self, eax, ecx=0):
        if self._cpuid:
            regs = (ctypes.c_uint * 4)()
            self._cpuid(regs, eax, ecx)
            return [regs[0], regs[1], regs[2], regs[3]]
```

#### Hypervisor���
```python
# ���ECX�Ĵ����ĵ�31λ (0x80000000)
if ecx & (1 << 31):
    self._add_vm_signature(5)
```

#### �ڴ����÷���
```python
total_ram_gb = mem_status.ullTotalPhys / (1024 ** 3)
if total_ram_gb.is_integer():  # �����ͨ���������ڴ�����
    self._add_vm_signature(1)
```

### 4. ���Ȩ��ϵͳ

�������ʹ�ü�Ȩ����ϵͳ��
- ��ָ�꣺Ȩ��1�����ڴ����ã�
- �е�ָ�꣺Ȩ��2-3������̡��ļ���⣩
- ǿָ�꣺Ȩ��4-5����CPUID��CPUƷ�ƣ�

�������Ŷȼ��㣺
```
vm_confidence = (vm_signatures / total_signatures) * 100
```

## ʹ�÷���

### ��װ����
```bash
pip install pywin32 ctypes
```

### ���г���
```bash
python main.py
```

### ���н��
- ��⵽���������ʾ"��⵽�������������"
- ��⵽���������ʾ"�������������������"
- ���ͨ��Windows��Ϣ����ʾ

## ����߼�˵��

### �ϸ�ģʽ
```python
if strict_mode and physical_signatures > 0:
    return False  # �����
```

### ���Ŷ�ģʽ
```python
return vm_confidence > 80  # 80%��ֵ
```

[! IMPORTANT]
>## ע������
>
>1. ��Ҫ����ԱȨ�޷���ע����ϵͳ�ļ�
>2. ��Hyper-V�����п��ܼ��Ϊ����������Ԥ�ڣ�
>3. ���ּ����ܱ��߼�������ƹ�
>4. �ڴ����������Windowsϵͳ

[! TIP]
>## ������˵��
>
>�ù���ʹ��������Windows API��
>- `__cpuidex` (CPUIDָ��)
>- `GlobalMemoryStatusEx` (�ڴ���)
>- `GetSystemTime` (ʱ�����)

���м������û��ռ���У������޸�ϵͳ���û��ļ���

## ���֤

����Ŀ���� **GNU General Public License v3.0** (GPL-3.0) ���֤������

Copyright (C) 2025 HOE Software Team
