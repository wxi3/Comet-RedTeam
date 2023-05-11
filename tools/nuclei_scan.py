import json
import os.path
import random
import shlex
import string
import subprocess


basedir = os.path.abspath(os.path.dirname(__file__))
TMP_PATH = os.path.join(basedir, 'tmp')
def random_choices(k=6):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=k))

def exec_system(cmd, **kwargs):
    cmd = " ".join(cmd)
    timeout = 4 * 60 * 60

    if kwargs.get('timeout'):
        timeout = kwargs['timeout']
        kwargs.pop('timeout')

    completed = subprocess.run(shlex.split(cmd), timeout=timeout, check=False, close_fds=True, **kwargs)

    return completed
class NucleiScan(object):
    def __init__(self, targets: list):
        self.targets = targets

        tmp_path = TMP_PATH
        rand_str = random_choices()

        self.nuclei_target_path = os.path.join(tmp_path,
                                               "nuclei_target_{}.txt".format(rand_str))

        self.nuclei_result_path = os.path.join(tmp_path,
                                               "nuclei_result_{}.json".format(rand_str))

        self.nuclei_bin_path = "nuclei"

    def _delete_file(self):
        try:
            os.unlink(self.nuclei_target_path)
            os.unlink(self.nuclei_result_path)
        except Exception as e:
            pass

    def check_have_nuclei(self) -> bool:
        command = [self.nuclei_bin_path, "-version"]
        try:
            pro = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if pro.returncode == 0:
                return True
        except Exception as e:
            pass

        return False

    def _gen_target_file(self):
        os.makedirs(os.path.dirname(self.nuclei_target_path), exist_ok=True)
        with open(self.nuclei_target_path, "w+") as f:
            for domain in self.targets:
                domain = domain.strip()
                if not domain:
                    continue
                f.write(domain + "\n")

    def dump_result(self) -> list:

        with open(self.nuclei_result_path, "w+") as f:
            lines = f.readlines()

        results = []
        for line in lines:
            data = json.loads(line)
            item = {
                "template_url": data.get("template-url", ""),
                "template_id": data.get("template-id", ""),
                "vuln_name": data.get("info", {}).get("name", ""),
                "vuln_severity": data.get("info", {}).get("severity", ""),
                "vuln_url": data.get("matched-at", ""),
                "curl_command": data.get("curl-command", ""),
                "target": data.get("host", "")
            }
            results.append(item)

        return results

    def exec_nuclei(self):
        self._gen_target_file()

        command = [self.nuclei_bin_path, "-duc",
                   "-tags cve",
                   "-severity low,medium,high,critical",
                   "-type http",
                   "-l {}".format(self.nuclei_target_path.replace('\\', '\\\\')),
                   "-json",
                   "-stats",
                   "-stats-interval 60",
                   "-o {}".format(self.nuclei_result_path.replace('\\', '\\\\')),
                   ]


        exec_system(command, timeout=12*60*60)

    def run(self):
        if not self.check_have_nuclei():
            print("not found nuclei")
            return

        self.exec_nuclei()
        results = self.dump_result()

        # 删除临时文件
        self._delete_file()

        return results


def nuclei_scan(targets: list):
    if not targets:
        return []

    n = NucleiScan(targets=targets)
    return n.run()

