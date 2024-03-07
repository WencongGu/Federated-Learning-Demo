import datetime
import os
import time

import rsa
import json


class MyRSA:
    DEFAULT_EXPONENT = 65537
    count = 0

    def __init__(self, name, n_bits=512, keys_save_path="public_keys",
                 exponent=DEFAULT_EXPONENT):
        assert n_bits > 16, "key too small"
        self.name = name
        self.keys_save_path = keys_save_path
        self.public_key, self.private_key = rsa.newkeys(n_bits, exponent=exponent)  # 完美主义者：希望e可控
        self.N = self.private_key.n
        self.e = self.private_key.e
        MyRSA.count += 1

    def encrypt(self, m, obj_public_key: str = None):
        if obj_public_key is None:
            public_key = self.public_key
        else:
            public_key = obj_public_key
        return rsa.encrypt(str(m).encode('utf-8'), public_key)

    def decrypt(self, c, signed_from_private_key: str = None):  # 可以用于验证签名
        if signed_from_private_key is None:  # 有值时为签名
            key = self.private_key
        else:
            key = signed_from_private_key
        return rsa.decrypt(c, key).decode('utf-8')

    @staticmethod
    def get_public_key_from_json(obj: str, path_="public_keys"):
        with open(path_ + '/' + obj + "_key.json", encoding='utf-8') as file:
            data = json.load(file)
        return rsa.PublicKey(data[obj][0], data[obj][1])


class Server:
    count = 0

    def __init__(self, dir_name="public_keys", if_get_all=False, if_clear=False, if_record=False, update_now=True):
        self.dir_name = dir_name
        self.if_clear = if_clear
        self.if_record = if_record
        self.update_now = update_now

        self.clients = {}  # 用户对象字典
        self.users = {}  # 键-用户名，值-[n,e]，即数组形式的公钥
        self.users_key = {}  # 键-用户名，值-PublicKey(n,e)，公钥对象，主要使用这个数据
        self.users_name = []  # 用户名数组

        self.temp_msg = []
        self.msg_box = {}

        self.unsigned_users = {"NAMES": []}  # 键-用户名，值-[n,e]，从json文件中加载的用户
        self.file_list = []
        self.new_client_paths = set()
        self.time = datetime.datetime.now().strftime("%m/%d/%Y, %H:%M:%S")
        Server.count += 1
        self.server_id = Server.count
        print(f"创建服务器id{self.server_id}: {self.time}")
        if if_get_all:
            self.get_all_users()

    def __del__(self):
        if self.if_record:  # 错误：time类型不能被写入json文件，先不用这个
            data = {"server_id": f"{self.server_id}", "users": self.users_name,
                    "unsigned_users": self.unsigned_users, "file_save_path": self.dir_name}
            for j in self.clients:
                data[j.name + "message_sent"] = j.sent_message_box_all
                data[j.name + "message_received"] = j.message_box_all
            with open(self.dir_name + '/' + "Server_" + f"{self.server_id}" + "_record_.json", 'w+',
                      encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=4, skipkeys=True)
        if len(self.new_client_paths) > 0 and self.if_clear:
            print(f"服务器{self.server_id}关闭，删除所有新用户json数据，{self.time}")
            for p in self.new_client_paths:
                os.remove(p)
        else:
            print(
                    f"服务器{self.server_id}关闭，最后登录了{len(self.clients)}个用户，json信息保存在\'./{self.dir_name}\'目录下，{self.time}")

    def client_login(self, client):
        client.logout()
        if client.name in self.users_name:
            print("用户名已存在，将覆盖原用户")
        self.clients[client.name] = client
        client.write_json(path_=self.dir_name)
        client.user_server = self
        if client.name not in self.users_name:  # 服务器(user_names、users、user_key)已加载的用户
            self.users_name.append(client.name)
        self.users_key[client.name] = client.public_key
        self.users[client.name] = (client.public_key.n, client.public_key.e)
        self.new_client_paths.add(self.dir_name + '/' + client.name + "_key.json")
        print(f"用户{client.name}登录Server{self.server_id}")

    def client_logout(self, client):
        if client.name not in self.users_name:
            print("用户未登录，无需登出")
            return
        client.user_server = None
        self.users_name.remove(client.name)
        del self.users[client.name], self.clients[client.name], self.users_key[client.name]
        print(f"用户{client.name}登出Server{self.server_id}")
        os.remove(self.dir_name + '/' + client.name + "_key.json")
        print(f"{self.dir_name}目录下{client.name}相关json文件已删除")

    def msg_process(self, msg_, from_: str, to_: str, t=None):
        self.temp_msg.append((to_, msg_, from_, t))
        if self.update_now:
            self.update()

    def update(self):
        t = datetime.datetime.now().strftime("%m/%d/%Y, %H:%M:%S")
        if len(self.temp_msg) == 0:
            print("消息已更新")
            return
        for j in self.temp_msg:
            self.get_client(j[0]).receive(j[1], j[2], j[3])
        print(f"{len(self.temp_msg)}条消息已更新")
        if self.if_record:
            self.msg_box[t] = self.temp_msg
        self.temp_msg = []

    def get_client(self, name: str):
        # assert name in self.users_name, "用户不在服务器中"
        if name not in self.users_name:
            return None
        return self.clients[name]

    def login_by_name(self, name: str):
        self.client_login(self.get_client(name))

    def logout_by_name(self, name: str):
        self.client_logout(self.get_client(name))

    def get_all_users(self, path_=None):
        if path_ is None:
            path_ = self.dir_name
        files_dirs = os.listdir(path_)
        for f in files_dirs:
            file_type = f[-len("_key.json"):]
            if os.path.isfile(path_ + "/" + f) and file_type == "_key.json":
                with open(path_ + "/" + f, encoding='utf-8') as file:
                    data = json.load(file)
                self.file_list.append(path_ + "/" + f)
                name = f[:-len('_key.json')]
                self.unsigned_users["NAMES"].append(name)
                self.unsigned_users.update(data)
        print("从本地" + f"{path_}" + "路径中的json文件中加载了", len(self.unsigned_users["NAMES"]),
              "个未登录用户（无法获取私钥），使用server.client_login(your_client)登录。\n", self.unsigned_users["NAMES"])
        return self.users

    def add_user_json(self, name, path_):
        with open(path_ + "/" + name + "_key.json", encoding='utf-8') as file:
            data = json.load(file)
        self.unsigned_users["NAMES"].append(name)
        self.unsigned_users.update(data)
        if path_ != self.dir_name:
            with open(self.dir_name + '/' + name + "_key.json", 'w+', encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=4)
        print("从" + f"{path_}" + "路径中的json文件中加载了未登录用户", name,
              "（无法获取私钥），使用server.client_login(your_client)登录。目前未登录用户：\n", self.unsigned_users["NAMES"])

    def get_user_key(self, name: str, path_=None):
        if path_ is not None:
            return MyRSA.get_public_key_from_json(name, path_)
        else:
            assert name in self.users_name, "没有用户"
            return self.users_key[name]

    # def get_dir(self, path=None):
    #     if path is None:
    #         path = self.dir_name
    #     dir_list = []
    #     dirs = os.listdir(path)
    #     for f in dirs:
    #         if os.path.isdir(path + "/" + f):
    #             dir_list.append(path + "/" + f)
    #     return dir_list


class Client:
    count = 0

    def __init__(self, name, my_server: Server = None, path_="public_keys"):
        self.name = name  # 区分客户端的唯一标识

        self.path = path_
        self.__client_rsa = MyRSA(self.name, keys_save_path=self.path)
        print(f"用户{name}已保存")
        self.__private_key = self.__client_rsa.private_key
        self.public_key = self.__client_rsa.public_key
        Client.count += 1

        self.message_box = {}
        self.sent_message_box = {}
        self.message_box_all = []
        self.sent_message_box_all = []
        self.my_sent_box = {}
        self.my_receive_box = {}

        self.data = {self.name: (self.public_key.n, self.public_key.e)}
        self.user_server = None
        if my_server is not None:
            self.login(my_server)
        else:
            print(f"用户{name}在未登录状态")
            self.user_server = None

    def login(self, to_server):
        self.logout()
        to_server.client_login(self)

    def logout(self):  # , from_server:Server=None):
        if self.user_server is None:
            return
        self.user_server.client_logout(self)

    def send(self, msg_, to_name: str):
        assert self.user_server is not None, "未登录任何Server"
        # assert to_name in self.user_server.users_name, f"服务器中无该用户{to_name}"
        # 还是不要让客户端直接访问服务器数据比较好，但是public_key是可以访问的，可以用server.get_user_key(name)
        t = datetime.datetime.now().strftime("%m/%d/%Y, %H:%M:%S")
        stamp = time.time()
        c_msg = self.__client_rsa.encrypt(msg_, self.user_server.get_user_key(to_name))
        self.user_server.msg_process(c_msg, self.name, to_name, t)
        self.sent_message_box[to_name] = (msg_, c_msg, "to: ", to_name, "at: ", t)
        self.sent_message_box_all.append((msg_, c_msg, "to: ", to_name, "at: ", t))
        self.my_sent_box[(to_name, stamp)] = (msg_, c_msg)
        return c_msg

    def receive(self, c_msg, from_name: str, time_=None):
        t = datetime.datetime.now().strftime("%m/%d/%Y, %H:%M:%S")
        stamp = time.time()
        msg_ = self.__client_rsa.decrypt(c_msg)
        self.message_box[from_name] = (msg_, "from: ", from_name, "update at: ", t, "sent at: ", time_)
        self.message_box_all.append((msg_, "from: ", from_name, "update at: ", t, "sent at: ", time_))
        self.my_receive_box[(from_name, stamp)] = (c_msg, msg_)
        return msg_

    def write_json(self, path_=None):
        if path_ is None:
            path_ = self.path
        with open(path_ + '/' + self.name + "_key.json", 'w+', encoding="utf-8") as f:
            json.dump(self.data, f, ensure_ascii=False, indent=4)

    def status_change(self):
        pass


def batch_login(to_server, *clients):
    for j in clients:
        to_server.client_login(j)


if __name__ == "__main__":
    path = "public_keys"

    test_client1 = Client("test_client1", Server())
    test_client2 = Client("test_client2", Server())

    server = Server()
    server.client_login(test_client2)
    test_client2 = Client("test_client2")
    server.client_login(test_client2)
    alice = Client("alice", server)
    bob = Client('bob', server)
    carol = Client("carol", server)
    eva = Client("eva", server)
    david = Client('david', server)
    faiz = Client('faiz', server)
    time.sleep(1)

    alice.logout()
    server.client_logout(bob)
    test_client1.login(server)
    server.client_login(test_client2)

    while True:
        i = int(input(
                f"选择你的身份序号 (1~{len(server.users_name)})，输入 0 退出。当前服务端有用户：\n{server.users_name}\n"))
        if i == 0:
            break
        elif i > len(server.users_name) or i < 0:
            print(f"用户序号范围：1~{len(server.users_name)}")
            continue
        identity = server.get_client(server.users_name[i - 1])
        # identity = alice
        print("你的身份是：", identity.name)
        choice = int(input(
                f"输入要发送的对象序号 (1~{len(server.users_name)})，输入 0 退出。当前服务端有用户：\n{server.users_name}\n"))
        if choice == 0:
            break
        elif choice > len(server.users_name) or choice < 0:
            print(f"用户序号范围：1~{len(server.users_name)}")
            continue
        to = server.users_name[choice - 1]
        msg = input(f"将发送给：{to}\n输入你要发送的消息，消息将作为字符串加密：\n")
        identity.send(msg, to)
    for i in server.clients.values():
        print(i.name, i.message_box_all, i.sent_message_box_all)
    print(server.users_name, '\n',
          server.users, '\n',
          server.users_key, '\n',
          server.clients, '\n',
          server.new_client_paths, '\n',
          server.file_list)
