import ctypes
import os
import subprocess
#import sys  #(删除307/315行注释时删除此行注释)
import time
import winreg
import random


# ====================== CPUID类 ======================
class CPUID:
    """CPUID指令读取"""

    def __init__(self):
        try:
            # 尝试使用Windows内核中的__cpuidex函数
            self._cpuid = ctypes.WinDLL('kernel32').__cpuidex
            self._cpuid.argtypes = [ctypes.POINTER(ctypes.c_uint), ctypes.c_int, ctypes.c_int]
            self._cpuid.restype = None
        except AttributeError:
            # 备用方案：使用更简单的检测方法
            self._cpuid = None

    def __call__(self, eax, ecx=0):
        if self._cpuid:
            regs = (ctypes.c_uint * 4)()
            self._cpuid(regs, eax, ecx)
            return [regs[0], regs[1], regs[2], regs[3]]
        else:
            # 备用检测方法
            return [0, 0, 0, 0]


# ====================== 检测核心类 ======================
class VMDetector:
    def __init__(self, strict_mode=True):
        self.strict_mode = strict_mode
        self.cpuid = CPUID()
        self.detection_results = {
            "vm_signatures": 0,
            "physical_signatures": 0,
            "vm_confidence": 0,
            "physical_confidence": 0
        }

    def run_detection(self):
        """执行所有检测方法"""
        # 随机化检测顺序以增加对抗性
        detection_methods = [
            self._check_basic_signatures,
            self._check_hardware_features,
            self._check_behavior_indicators,
            self._check_hypervisor_presence
        ]
        random.shuffle(detection_methods)

        for method in detection_methods:
            method()

        # 计算最终置信度
        total = max(1, self.detection_results["vm_signatures"] +
                    self.detection_results["physical_signatures"])

        self.detection_results["vm_confidence"] = (
                self.detection_results["vm_signatures"] / total * 100
        )
        self.detection_results["physical_confidence"] = (
                self.detection_results["physical_signatures"] / total * 100
        )

        return self.detection_results

    def is_virtualized(self):
        """判断是否在虚拟机环境中"""
        results = self.run_detection()

        # 严格模式：检测到任何实体机特征即停止
        if self.strict_mode and results["physical_signatures"] > 0:
            return False

        # 置信度模式：虚拟机置信度必须高于80%
        return results["vm_confidence"] > 80

    def _add_vm_signature(self, weight=1):
        """添加虚拟机特征"""
        self.detection_results["vm_signatures"] += weight

    def _add_physical_signature(self, weight=1):
        """添加实体机特征"""
        self.detection_results["physical_signatures"] += weight

    def _check_basic_signatures(self):
        """基础特征检测（注册表/文件/进程）"""
        # 注册表检测
        reg_keys = [
            (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\SystemInformation", "SystemProductName"),
            (winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\BIOS", "SystemProductName"),
            (winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\BIOS", "SystemManufacturer"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\VMware, Inc.\VMware Tools", "")
        ]

        vm_keywords = ["vmware", "virtual", "qemu", "kvm", "hyper-v", "vbox"]
        physical_keywords = ["lenovo", "dell", "asus", "acer", "hp", "hpe", "huawei", "microsoft surface"]

        for hkey, subkey, value_name in reg_keys:
            try:
                with winreg.OpenKey(hkey, subkey) as key:
                    # 处理空值名称
                    if value_name:
                        value, _ = winreg.QueryValueEx(key, value_name)
                    else:
                        value = subkey.split("\\")[-1]  # 使用键名作为值

                    value = str(value).lower()

                    if any(kw in value for kw in vm_keywords):
                        self._add_vm_signature(2)

                    if any(kw in value for kw in physical_keywords):
                        self._add_physical_signature(3)
            except:
                pass

        # 文件检测
        vm_files = [
            r"C:\Windows\System32\drivers\vmmouse.sys",
            r"C:\Windows\System32\drivers\vmhgfs.sys",
            r"C:\Windows\System32\vboxhook.dll",
            r"C:\Windows\System32\drivers\VBoxGuest.sys"
        ]
        for file in vm_files:
            if os.path.exists(file):
                self._add_vm_signature(3)

        # 进程检测
        try:
            output = subprocess.check_output(
                "tasklist /fo csv /nh",
                shell=True,
                text=True,
                stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW
            ).lower()

            vm_processes = ["vmtoolsd.exe", "vmacthlp.exe", "vboxservice.exe"]
            for proc in vm_processes:
                if proc in output:
                    self._add_vm_signature(2)
        except:
            pass

    def _check_hardware_features(self):
        """硬件特征检测"""
        # 检查CPU品牌
        try:
            output = subprocess.check_output(
                "wmic cpu get name",
                shell=True,
                text=True,
                stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            cpu_brand = " ".join(output.strip().splitlines()[1:]).lower()

            vm_keywords = ["vmware", "virtualcpu", "hypervisor", "qemu", "kvm"]
            physical_keywords = ["intel", "amd", "core", "ryzen", "xeon"]

            if any(kw in cpu_brand for kw in vm_keywords):
                self._add_vm_signature(4)

            if any(kw in cpu_brand for kw in physical_keywords):
                self._add_physical_signature(4)
        except:
            pass

        # 内存检测
        class MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = [
                ("dwLength", ctypes.c_ulong),
                ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong),
            ]

        mem_status = MEMORYSTATUSEX()
        mem_status.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(mem_status)):
            total_ram_gb = mem_status.ullTotalPhys / (1024 ** 3)

            # 虚拟机通常有整数(1024)内存配置
            if total_ram_gb.is_integer():
                self._add_vm_signature(1)
            else:
                self._add_physical_signature(1)

        # MAC地址检测
        try:
            output = subprocess.check_output(
                "getmac /v /fo csv /nh",
                shell=True,
                text=True,
                stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW
            )

            vm_mac_prefixes = ["00:0C:29", "00:1C:14", "00:50:56", "08:00:27"]
            physical_mac_prefixes = ["A4:4C:C8", "98:FA:9B", "F0:79:60", "D0:50:99"]

            for line in output.splitlines():
                if line.strip():
                    parts = line.split(',')
                    if len(parts) >= 2:
                        mac = parts[2].strip().replace('"', '').upper()
                        if any(mac.startswith(prefix) for prefix in vm_mac_prefixes):
                            self._add_vm_signature(3)
                        if any(mac.startswith(prefix) for prefix in physical_mac_prefixes):
                            self._add_physical_signature(3)
        except:
            pass

    def _check_behavior_indicators(self):
        """行为指标检测"""
        # 时间漂移检测
        try:
            start = time.perf_counter_ns()
            time.sleep(0.1)
            end = time.perf_counter_ns()
            elapsed_ns = end - start

            # 物理机<110ms，虚拟机>120ms
            if elapsed_ns > 120_000_000:  # 120ms
                self._add_vm_signature(2)
            elif elapsed_ns < 105_000_000:  # 105ms
                self._add_physical_signature(1)
        except:
            pass

        # 指令执行延迟检测
        try:
            delays = []
            for _ in range(10):
                start = time.perf_counter_ns()
                ctypes.windll.kernel32.GetSystemTime(ctypes.c_void_p())
                end = time.perf_counter_ns()
                delays.append(end - start)

            avg_delay = sum(delays) / len(delays)

            # 物理机通常<100ns，虚拟机>200ns
            if avg_delay > 200:
                self._add_vm_signature(2)
            elif avg_delay < 150:
                self._add_physical_signature(2)
        except:
            pass

    def _check_hypervisor_presence(self):
        """虚拟机监控程序检测"""
        # CPUID检测
        try:
            # 获取功能1信息 (EAX=1)
            _, _, ecx, _ = self.cpuid(1, 0)
            # 检查ECX寄存器的第31位 (0x80000000)
            if ecx & (1 << 31):
                self._add_vm_signature(5)
            else:
                self._add_physical_signature(1)
        except:
            pass

        # Windows Hypervisor(Hyper-V)检测
        try:
            result = subprocess.run(
                "systeminfo",
                capture_output=True,
                text=True,
                shell=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            if "Hyper-V Requirements" in result.stdout:
                vm_lines = [line for line in result.stdout.splitlines()
                            if "Hyper-V" in line and "Yes" in line]
                if vm_lines:
                    self._add_vm_signature(3)
        except:
            pass


# ====================== 主程序逻辑 ======================
def is_running_in_vm():
    """判断是否在虚拟机中运行"""
    # 创建检测器（严格模式）
    detector = VMDetector(strict_mode=True)
    return detector.is_virtualized()


if __name__ == "__main__":
    # 隐藏控制台窗口
    ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)

    if is_running_in_vm():
        # 显示虚拟机运行提示并退出(删除第307行注释)
        ctypes.windll.user32.MessageBoxW(0, "检测到正在虚拟机运行。", "信息", 0x40)
        #sys.exit(1)
    else:
        # 显示实体机运行提示并退出(删除第315行注释)
        ctypes.windll.user32.MessageBoxW(0,"程序不在虚拟机环境运行","信息",0x40)
        #sys.exit(1)

