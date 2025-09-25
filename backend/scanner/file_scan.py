import subprocess
import platform

def scan_file(file_path):
    if platform.system() == "Windows":
        # Adjust path to your clamscan.exe location
        clamscan_path = r"C:\Program Files\ClamAV\clamscan.exe"
        try:
            process = subprocess.run([clamscan_path, file_path], capture_output=True, text=True, timeout=60)
            output = process.stdout
            infected = "Infected files: 0" not in output
            malware = None
            if infected:
                for line in output.splitlines():
                    if file_path in line and "FOUND" in line:
                        malware = line.split("FOUND")[0].strip()
                        break
            return {"infected": infected, "malware": malware}
        except Exception as e:
            print(f"Error scanning file with clamscan: {e}")
            return {"infected": False, "malware": None}
    else:
        import clamd
        try:
            cd = clamd.ClamdUnixSocket()
            scan_result = cd.scan(file_path)
            status = scan_result[file_path][0]
            malware = scan_result[file_path][1] if status == 'FOUND' else None
            return {
                "infected": status == 'FOUND',
                "malware": malware,
            }
        except Exception as e:
            print(f"Error scanning file with clamd: {e}")
            return {"infected": False, "malware": None}
