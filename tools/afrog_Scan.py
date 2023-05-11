import json
import os.path
import random
import shlex
import string
import subprocess
import functions

basedir = os.path.abspath(os.path.dirname(__file__))
TMP_PATH = os.path.join(basedir, 'tmp')

parent_path = os.path.dirname(basedir)
REPORT_PATH = os.path.join(parent_path, 'reports')
def random_choices(k=6):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=k))

def exec_system(cmd, **kwargs):
    cmd = " ".join(cmd)
    timeout = 4 * 60 * 60

    if kwargs.get('timeout'):
        timeout = kwargs['timeout']
        kwargs.pop('timeout')
    print(shlex.split(cmd))
    completed = subprocess.run(shlex.split(cmd), timeout=timeout, check=False, close_fds=True, **kwargs)

    return completed
class afrogScan(object):
    def __init__(self,taskname, targets: list) -> object:
        self.taskname = taskname
        self.targets = targets

        tmp_path = TMP_PATH
        rand_str = random_choices()
        self.json_path = "afrog_result_{}.json".format(rand_str)

        self.afrog_target_path = os.path.join(tmp_path,
                                               "afrog_target_{}.txt".format(rand_str))

        self.afrog_result_path = os.path.join(REPORT_PATH,
                                               self.json_path)

        self.afrog_bin_path = os.path.join(basedir, 'afrog.exe')

    def _delete_file(self):
        try:
            os.unlink(self.afrog_target_path)
            os.unlink(self.afrog_result_path)
        except Exception as e:
            pass

    def check_have_afrog(self) -> bool:
        command = [self.afrog_bin_path, "-h"]
        print(command)
        try:
            pro = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if pro.returncode == 0:
                return True
        except Exception as e:
            print(e)

        return False

    def _gen_target_file(self):
        with open(self.afrog_target_path, "w+") as f:
            for domain in self.targets:
                domain = domain.strip()
                if not domain:
                    continue
                f.write(domain + "\n")
    def dump_result(self) -> list:
        with open(self.afrog_result_path, "r+") as f:
            data = json.load(f)


        results = []
        for item in data:
            result = {
                "task_name":self.taskname,
                "vuln_name": item["name"],
                "vuln_severity": item["severity"],
                "vuln_url": item["url"],
            }
            results.append(result)
        collection = functions.db['vulnInfo']
        collection.insert_many(data)
        return results


    def exec_afrog(self):
        self._gen_target_file()
        command = [self.afrog_bin_path.replace('\\', '\\\\'),
                   "-silent",
                   "-duc",
                   "-T {}".format(self.afrog_target_path.replace('\\', '\\\\')),
                   "-j {}".format(self.json_path),
                   ]
        print(command)
        exec_system(command, timeout=12*60*60)

    def run(self):
        if not self.check_have_afrog():
            print("not found afrog")
            return

        self.exec_afrog()
        results = self.dump_result()

        # 删除临时文件
        self._delete_file()

        return results


def afrog_scan(targets: list,taskname):
    if not targets:
        return []
    n = afrogScan(targets=targets,taskname=taskname)
    return n.run()

