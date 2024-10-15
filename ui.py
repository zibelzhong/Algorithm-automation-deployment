import time

import paramiko
import os
from tkinter import ttk
import tkinter as tk
from tkinter import filedialog
from PIL import ImageTk, Image
import re
from datetime import datetime

# 日志文本框
log_text = None


def deploy_algorithm():
    """
    函数部署时信息输入
    :return:
    """
    host = entry_remote_host.get()  # 远程主机的地址
    remote_password = entry_remote_password.get()  # 远程主机的密码
    username = entry_remote_username.get()  # 远程主机的用户名
    local_file_path_folder = entry_local_file_folder.get()  # 算法文件夹
    port = entry_port.get()  # 远程主机端口号
    local_file_path = entry_local_file.get()  # 算法运行的主函数
    target_file = entry_target_file_folder.get()  # 服务器上部署算法的路径
    log_text.insert(tk.END, f"远程主机地址: {host}\n")
    log_text.insert(tk.END, f"远程主机用户名: {username}\n")
    log_text.insert(tk.END, f"远程主机密码: {remote_password}\n")
    log_text.insert(tk.END, f"端口号: {port}\n")
    log_text.insert(tk.END, f"算法文件夹: {local_file_path_folder}\n")
    log_text.insert(tk.END, f"运行主函数: {local_file_path}\n")
    log_text.insert(tk.END, f"算法部署路径: {target_file}\n")
    log_text.see(tk.END)

    if host and port and username and remote_password and local_file_path_folder and target_file:
        log_text.insert(tk.END, "开始部署算法...\n")
        deploy_algorithm_to_server(host, port, username, remote_password, local_file_path_folder, target_file)


def deploy_algorithm_to_server(host, port, username, password, local_file_path, remote_dir):
    """
    部署算法到服务器上
    :param host:
    :param port:
    :param username:
    :param password:
    :param local_file_path:
    :param remote_dir:
    :return:
    """

    # 创建 SSH 客户端
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        # 连接到远程服务器
        ssh.connect(host, port, username, password)
        # 检查SSH连接状态
        if not ssh.get_transport().is_active():
            log_text.insert(tk.END, "服务器连接失败\n")
        # 创建 SFTP 客户端
        sftp = ssh.open_sftp()
        # 切换到远程目录
        try:
            sftp.chdir(remote_dir)
        except IOError:
            # 如果远程目录不存在，则创建目录
            sftp.mkdir(remote_dir)
            sftp.chdir(remote_dir)
        # 遍历本地目录
        for root_root, dirs, files in os.walk(local_file_path):
            # 计算相对路径
            rel_path = os.path.relpath(root_root, local_file_path)
            if rel_path != '.':
                current_remote_dir = os.path.join(remote_dir, rel_path).replace(os.path.sep, '/')
                try:
                    sftp.chdir(current_remote_dir)
                except IOError:
                    # 创建目录
                    try:
                        sftp.chdir(current_remote_dir)
                    except IOError:
                        sftp.mkdir(current_remote_dir)
                        sftp.chdir(current_remote_dir)
            # 上传文件
            for file in files:
                local_file_path_temp = os.path.join(root_root, file).replace(os.path.sep, '/')
                remote_file_path = os.path.join(sftp.getcwd(), file).replace(os.path.sep, '/')
                sftp.put(local_file_path_temp, remote_file_path)
        log_text.insert(tk.END, "算法部署完成\n")

    except Exception as e:
        log_text.insert(tk.END, f"发生错误: {e}\n")


def start_algorithm_service():
    """
    算法启动
    :return:
    """
    host = entry_remote_host.get()  # 远程主机的地址
    remote_password = entry_remote_password.get()  # 远程主机的密码
    username = entry_remote_username.get()  # 远程主机的用户名
    port = entry_port.get()  # 远程主机端口号
    local_file_path = entry_local_file.get()  # 算法运行的主函数
    target_file = entry_target_file_folder.get()  # 服务器上部署算法的路径
    config_file = entry_config_file.get()  # 获取配置文件信息
    # 算法启动脚本
    config_data = config_file.split("/")[-1]  # 获取配置文件的函数名（带有后缀）
    local_file = local_file_path.split("/")[-1].split(".")[0]  # 获取主函数的函数名[不带有后缀名]
    script_name = f"gunicorn --config={config_data}  {local_file}:app"

    if host and port and username and remote_password and target_file and script_name:
        log_text.insert(tk.END, "开始启动算法服务...\n")
        start_algorithm_service_impl(host, port, username, remote_password, target_file, script_name, config_file)


def start_algorithm_service_impl(host, port, username, password, remote_dir, script_name, config_file):
    """
    算法启动的核心函数
    :param host:
    :param port:
    :param username:
    :param password:
    :param remote_dir:
    :param config_file:算法运行的配置文件
    :param script_name: #运行算法启动的脚本
    :return:
    """
    # 创建 SSH 客户端
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        # 连接到远程服务器
        ssh.connect(host, port, username, password)
        # # 使用 -i 参数强制使用交互式 shell,算法启动命令
        stdin, stdout, stderr = ssh.exec_command(f"bash -i -c 'source ~/.bashrc && cd {remote_dir} && {script_name}'")
        log_text.insert(tk.END, "启动服务结果:\n")
        # 运行的日志打印到ui界面上
        # 获取日志的名称
        with open(config_file, 'r', encoding='utf-8') as file:
            content = file.read()
        start_string = "pidfile"
        end_string = "accesslog"
        pattern = rf"{re.escape(start_string)}(.*?){re.escape(end_string)}"
        match = re.search(pattern, content, re.DOTALL)
        if match:
            remaining_content = match.group(1).strip()
            log_name = remaining_content.split("./")[1].split("/")[0]  # 获取日志名称
            # 拼接服务器上日志路径
            log_path_server = os.path.join(remote_dir, log_name).replace(os.path.sep, '/') + "/gunicorn.log"
            # 打开SFTP会话
            sftp = ssh.open_sftp()
            # 读取文件内容
            time.sleep(2)
            try:
                with sftp.file(log_path_server, 'r') as file:
                    log_content = file.read().decode('utf-8')
                    # 对日志文件进行截取
                    get_latest_log_content(log_content, log_text)
            except Exception as e:
                log_text.insert(tk.END, "没有部署运行日志文件\n")
    except Exception as e:
        log_text.insert(tk.END, f"发生错误: {e}\n")
    finally:
        # 关闭 SSH 连接
        if ssh:
            ssh.close()


# 截取日志文件中最新的内容
def get_latest_log_content(log_file_path, log_text):
    """
    获取日志文件中最新的内容
    :param log_file_path:
    :param log_text:  ui文本框中的日志
    :return:
    """
    # 定义正则表达式匹配日志时间
    log_time_pattern = r'\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \+\d{4}\]'
    # 提取所有时间戳
    timestamps = []
    logs = log_file_path.split('\n')
    for log in logs:
        match = re.search(log_time_pattern, log)
        if match:
            timestamp_str = match.group(1)  # 获取时间时间
            timestamps.append(datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S'))
    # 找到最新的时间戳（精确到分钟）
    latest_minute = max(timestamps).replace(second=0)
    # 提取最新时间精确到分钟的所有日志信息
    filtered_logs_index = []
    for index, log in enumerate(logs):
        # 找到最新日志的位置
        # 使用正则表达式匹配并提取第一个方括号内的内容
        match = re.search(log_time_pattern, log)  # 获取时间
        if match:
            timestamp_str = match.group(1)
            timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
            if timestamp.replace(second=0) == latest_minute:
                filtered_logs_index.append(index)
    if len(filtered_logs_index) == 0:
        log_text.insert(tk.END, "算法没有启动成功，请查找原因。\n")
        log_text.see(tk.END)  # 滚动到底部

    else:
        filter_log = logs[min(filtered_logs_index):]
        for log in filter_log:
            log_text.insert(tk.END, f"{log}\n")
            log_text.see(tk.END)  # 滚动到底部
        # 对结果进行判断
        last_open_bracket_index = filter_log[-2].rfind('[')
        last_close_bracket_index = filter_log[-2].rfind(']')
        # 提取最后一个方括号内的内容
        last_bracket_content = filter_log[-2][last_open_bracket_index + 1:last_close_bracket_index]
        if last_bracket_content == "ERROR":
            log_text.insert(tk.END, "算法启动失败\n")
            log_text.see(tk.END)  # 滚动到底部
        else:
            log_text.insert(tk.END, "算法启动成功\n")
            log_text.see(tk.END)  # 滚动到底部


def stop_algorithm_service():
    """
    算法停止
    :return:
    """
    host = entry_remote_host.get()  # 远程主机的地址
    remote_password = entry_remote_password.get()  # 远程主机的密码
    username = entry_remote_username.get()  # 远程主机的用户名
    port = entry_port.get()  # 远程主机端口号
    target_file = entry_target_file_folder.get()  # 服务器上部署算法的路径
    config_file = entry_config_file.get()  # 获取配置文件信息
    if host and port and username and remote_password and target_file:
        log_text.insert(tk.END, "开始停止算法服务...\n")
        stop_algorithm_service_impl(host, port, username, remote_password, target_file, config_file)


def choose_local_file():
    """
    选择本地文件
    :return:
    """
    file_path = filedialog.askopenfilename()
    entry_local_file.delete(0, tk.END)
    entry_local_file.insert(0, file_path)


def choose_config_file():
    """
    选择算法运行配置脚本
    :return:
    """
    file_path = filedialog.askopenfilename()
    entry_config_file.delete(0, tk.END)
    entry_config_file.insert(0, file_path)


def select_local_folder():
    """
    选择算法文件夹
    :return:
    """
    folder_path = filedialog.askdirectory()
    entry_local_file_folder.delete(0, tk.END)
    entry_local_file_folder.insert(0, folder_path)


def stop_algorithm_service_impl(host, port, username, password, remote_dir, config_file):
    """
    算法停止的核心函数
    逻辑:算法运行不成功，则不用运行停止服务的算法，如果算法启动成功，才需要运行算法停止服务
    """
    # 创建 SSH 客户端
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        # 连接到远程服务器
        ssh.connect(host, port, username, password)
        # 获取日志的名称
        with open(config_file, 'r', encoding='utf-8') as file:
            content = file.read()
        start_string = "pidfile"
        end_string = "accesslog"
        pattern = rf"{re.escape(start_string)}(.*?){re.escape(end_string)}"
        match = re.search(pattern, content, re.DOTALL)
        if match:
            remaining_content = match.group(1).strip()
            log_name = remaining_content.split("./")[1].split("/")[0]  # 获取日志名称
            # 拼接服务器上日志路径
            log_path_server = os.path.join(remote_dir, log_name).replace(os.path.sep, '/') + "/gunicorn.log"
            # 打开SFTP会话
            sftp = ssh.open_sftp()
            # 读取文件内容
            with sftp.file(log_path_server, 'r') as file:
                log_content = file.read().decode('utf-8')
        # 解析算法运行日志
        flag, pids = parse_log(log_content)
        if not flag:
            log_text.insert(tk.END, "算法没有启动，无需停止算法\n")
            log_text.see(tk.END)  # 滚动到底部
        else:
            for pid in pids:
                stdin, stdout, stderr = ssh.exec_command(f"kill -9 {pid}")
                stderr_output = stderr.read().decode('utf-8')
                log_text.insert(tk.END, f"{stderr_output}\n")
            log_text.insert(tk.END, "算法服务停止完成。\n")
            log_text.see(tk.END)  # 滚动到底部

    except Exception as e:
        log_text.insert(tk.END, f"发生错误: {e}\n")
    finally:
        # 关闭 SSH 连接
        if ssh:
            ssh.close()


# 解析日志
def parse_log(log_content):
    """
    解析算法日志，
    :param log_content:
    :return: 算法是否启动成功，启动成功后的PID为多少
    """
    if len(log_content) == 0:
        flag = False
        pids = []
    else:
        latest_log, latest_time = find_latest_log(log_content)
        # 判断算法是否运行成功
        # 找到最后一个方括号的位置
        last_open_bracket_index = latest_log[-1].rfind('[')
        last_close_bracket_index = latest_log[-1].rfind(']')
        # 提取最后一个方括号内的内容
        last_bracket_content = latest_log[-1][last_open_bracket_index + 1:last_close_bracket_index]
        if last_bracket_content == "ERROR":
            flag = False  # 算法没有运行成功
            pids = []
        else:
            flag = True  # 算法运行成功，需要获取所有运行成功的pid
            pids = []
            for log_list in latest_log:
                # 获取所有的pid信息
                # 找到最后一个方括号的位置
                last_open_bracket_index = log_list.rfind('[')
                last_close_bracket_index = log_list.rfind(']')
                # 找到倒数第二个方括号的位置
                second_last_open_bracket_index = log_list.rfind('[', 0, last_open_bracket_index)
                second_last_close_bracket_index = log_list.rfind(']', 0, last_close_bracket_index)
                # 提取倒数第二个方括号内的内容
                second_last_bracket_content = log_list[
                                              second_last_open_bracket_index + 1:second_last_close_bracket_index]
                pids.append(second_last_bracket_content)
            pids = set(pids)
    return flag, pids


def find_latest_log(logs):
    """
    在日志列表中找到最新的一条日志
    :param logs:
    :return:
    """
    logs = logs.strip().split('\n')
    latest_log = []
    latest_time = None
    for log in logs:
        # 获取日志最新时间
        log_time, flag = parse_log_time(log)
        if not flag:  # 没有时间
            continue
        else:
            if latest_time is None or ((log_time >= latest_time) & (log_time is not None)):
                latest_time = log_time  # 日志更新最新的时间
    #  获取最新时间对应的日志内容
    for log in logs:
        log_time, flag = parse_log_time(log)
        if not flag:  # 没有时间
            continue
        else:
            if latest_time is None or ((log_time >= latest_time) & (log_time is not None)):
                latest_log.append(log)

    return latest_log, latest_time


def parse_log_time(log_line):
    """
    解析日志行中的时间
    :param log_line:Q
    :return:
    """
    time_str = log_line.split(']')[0][1:]
    log_time_pattern = r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}'
    match = re.search(log_time_pattern, time_str)
    if match:
        time_obj = datetime.strptime(match.group(), '%Y-%m-%d %H:%M:%S')
        time_obj_minute = time_obj.replace(second=0, microsecond=0)  # 提取时间字符串
        time_obj_minute = time_obj_minute.strftime('%Y-%m-%d %H:%M %z')
        flag = True
    else:
        time_obj_minute = None
        flag = False
    return time_obj_minute, flag  # 解析时间字符串


if __name__ == '__main__':
    # 创建主窗口
    root = tk.Tk()
    root.title("Pyton算法部署工具")
    # 设置窗口大小
    root.geometry("800x600")
    # 加载 logo 图片
    img = Image.open("图标11.png")
    img = img.resize((110, 100))  # 将图片调整为宽100像素，高100像素
    # 将图片转换为ImageTk对象
    logo_image = ImageTk.PhotoImage(img)
    logo_label = tk.Label(root, image=logo_image)
    logo_label.place(x=0, y=0)  # 将logo放在左上角
    # 创建输入框框架
    input_frame = tk.Frame(root)
    input_frame.pack(pady=20)
    # 创建远程主机地址输入框
    label_remote_host = tk.Label(input_frame, text="服务器host:", font=("仿宋", 12))
    entry_remote_host = tk.Entry(input_frame, font=("仿宋", 12))
    label_remote_host.grid(row=0, column=0, sticky=tk.E, padx=5, pady=5)
    entry_remote_host.grid(row=0, column=1, padx=5, pady=5)
    # 创建端口号输入框
    label_port = tk.Label(input_frame, text="端口号:", font=("仿宋", 12))
    entry_port = tk.Entry(input_frame, font=("仿宋", 12))
    label_port.grid(row=1, column=0, sticky=tk.E, padx=5, pady=5)
    entry_port.grid(row=1, column=1, padx=5, pady=5)
    # 创建远程主机的用户名
    label_remote_username = tk.Label(input_frame, text="服务器用户名:", font=("仿宋", 12))
    entry_remote_username = tk.Entry(input_frame, font=("仿宋", 12))
    label_remote_username.grid(row=2, column=0, sticky=tk.E, padx=5, pady=5)
    entry_remote_username.grid(row=2, column=1, padx=5, pady=5)
    # 创建远程主机密码输入框
    label_remote_password = tk.Label(input_frame, text="服务器密码:", font=("仿宋", 12))
    entry_remote_password = tk.Entry(input_frame, font=("仿宋", 12))
    label_remote_password.grid(row=3, column=0, sticky=tk.E, padx=5, pady=5)
    entry_remote_password.grid(row=3, column=1, padx=5, pady=5)
    # 创建目标文件路径输入框

    label_target_file = tk.Label(input_frame, text="部署路径:", font=("仿宋", 12))
    entry_target_file_folder = tk.Entry(input_frame, font=("仿宋", 12))
    label_target_file.grid(row=4, column=0, sticky=tk.E, padx=5, pady=5)
    entry_target_file_folder.grid(row=4, column=1, padx=5, pady=5)
    # 创建算法文件夹
    label_target_file_folder = tk.Label(input_frame, text="算法文件夹:", font=("仿宋", 12))
    entry_local_file_folder = tk.Entry(input_frame, font=("仿宋", 12))
    button_choose_target_file_folder = tk.Button(input_frame, text="选择文件夹", command=select_local_folder,
                                                 font=("仿宋", 12))
    label_target_file_folder.grid(row=5, column=0, sticky=tk.E, padx=5, pady=5)
    entry_local_file_folder.grid(row=5, column=1, padx=5, pady=5)
    button_choose_target_file_folder.grid(row=5, column=2, padx=5, pady=5)
    # 创建主函数
    label_local_file = tk.Label(input_frame, text="算法主函数:", font=("仿宋", 12))
    entry_local_file = tk.Entry(input_frame, font=("仿宋", 12))
    button_choose_local_file = tk.Button(input_frame, text="选择文件", command=choose_local_file, font=("仿宋", 12))
    label_local_file.grid(row=6, column=0, sticky=tk.E, padx=5, pady=5)
    entry_local_file.grid(row=6, column=1, padx=5, pady=5)
    button_choose_local_file.grid(row=6, column=2, padx=5, pady=5)
    # 选择算法配置函数
    label_local_file = tk.Label(input_frame, text="运行配置脚本:", font=("仿宋", 12))
    entry_config_file = tk.Entry(input_frame, font=("仿宋", 12))
    button_choose_local_file = tk.Button(input_frame, text="选择文件", command=choose_config_file, font=("仿宋", 12))
    label_local_file.grid(row=7, column=0, sticky=tk.E, padx=5, pady=5)
    entry_config_file.grid(row=7, column=1, padx=5, pady=5)
    button_choose_local_file.grid(row=7, column=2, padx=5, pady=5)
    # 添加按钮
    # 创建按钮框架
    button_frame = tk.Frame(root)
    button_frame.pack(pady=20)
    # 创建按钮并设置宽度和间距
    button_deploy = tk.Button(button_frame, text="部署算法", command=deploy_algorithm, width=10)
    button_start = tk.Button(button_frame, text="启动算法服务", command=start_algorithm_service, width=10)
    button_stop = tk.Button(button_frame, text="停止算法服务", command=stop_algorithm_service, width=10)
    # 使用pack布局管理器，设置按钮水平等间距排列
    button_deploy.pack(side=tk.LEFT, padx=(10, 5))
    button_start.pack(side=tk.LEFT, padx=5)
    button_stop.pack(side=tk.LEFT, padx=(5, 10))

    # 创建日志框框架
    log_frame = tk.Frame(root)
    log_frame.pack(pady=20, fill=tk.BOTH, expand=True)

    # 创建滚动条
    scrollbar = ttk.Scrollbar(log_frame)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    # 创建日志文本框
    log_text = tk.Text(log_frame, height=10, yscrollcommand=scrollbar.set)
    log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    # 配置滚动条
    scrollbar.config(command=log_text.yview)
    # 添加一句话
    label_message = tk.Label(root, text="如有问题请联系仲昭林，电话：18325517516", font=("仿宋", 12))
    label_message.pack(pady=10)
    # 运行主循环
    root.mainloop()
