# CAGE Challenge 2 debugged

Another Cage 2 repo with a few fixes:

### Bug Fixes

1. **Fixed issue with 'Remove' action**: 
    
    *CybORG_plus_plus/Debugged_CybORG/CybORG/CybORG/Shared/Actions/AbstractActions/Remove.py*
    
    This was only a small issue that indicated (if you checked the action success) that a 'remove' action had succeeded even if no process had actually been removed. The initial version had  obs set to a true observation which would get returned frequently when StopProcess didn't occur.
    
    **Initially (~26):**
    
    ```python
            if len(sessions) > 0:
                session = choice(sessions)
                obs = Observation(True)
                # remove suspicious processes
                if self.hostname in parent_session.sus_pids:
                    for sus_pid in parent_session.sus_pids[self.hostname]:
                        action = StopProcess(session=self.session, agent=self.agent, target_session=session.ident, pid=sus_pid)
                        action.sim_execute(state)
                # remove suspicious files
                return obs
            else:
                return Observation(False)
    
    ```
    
    **Corrected (~26):**
    
    ```python
            if len(sessions) > 0:
                session = choice(sessions)
                obs = Observation(False)
    
                # remove suspicious processes
                if self.hostname in parent_session.sus_pids:
                    for sus_pid in parent_session.sus_pids[self.hostname]:
                        action = StopProcess(session=self.session, agent=self.agent, target_session=session.ident, pid=sus_pid)
                        obs = action.sim_execute(state)
    
                # remove suspicious files
                return obs
            else:
                return Observation(False)
    ```
    
2. **Corrected port number in DecoyVsftpd**
    
    *CybORG_plus_plus/Debugged_CybORG/CybORG/CybORG/Shared/Actions/ConcreteActions/DecoyVsftpd.py*
    
    This was a mistake in the port given in the returned Decoy instance. It was initially 80 (DcoyApache) and it should be 21.
    
     **Initially (~18):**
    
    ```python
        def make_decoy(self, host: Host) -> Decoy:
            del host
            return Decoy(service_name="vsftpd", name="vsftpd",
                    open_ports=[{'local_port':80, 'local_address':'0.0.0.0'}],
                    process_type="webserver", properties=["rfi"],
                    process_path="/usr/sbin")
    ```
    
    **Corrected (~18):**
    
    ```python
        def make_decoy(self, host: Host) -> Decoy:
            del host
            return Decoy(service_name="vsftpd", name="vsftpd",
                    open_ports=[{'local_port':21, 'local_address':'0.0.0.0'}],
                    process_type="webserver", properties=["rfi"],
                    process_path="/usr/sbin")
    ```
    
3. **Added Process Type in Internal_image.yaml**
    
    *CybORG_plus_plus/Debugged_CybORG/CybORG/CybORG/Shared/Scenarios/images/Internal_image.yaml*
    
    This Connection was missing a line about the Process Type which was causing the exploit EternalBlue to fail on Enterprise1 (which uses Internal_image.yaml).
    
     **Initially (~26):**
    
    ```python
      -Connections:
        - local_address: 0.0.0.0
          local_port: 445
        - local_address: 0.0.0.0
          local_port: 139
        PID: 4
        PPID: 372
        Process Name: smss.exe
        Username: SYSTEM
    ```
    
    **Corrected (~26):**
    
    ```python
      -Connections:
        - local_address: 0.0.0.0
          local_port: 445
        - local_address: 0.0.0.0
          local_port: 139
        PID: 4
        PPID: 372
        Process Name: smss.exe
        Username: SYSTEM
        Process Type: smb
    ```
    

4. **Corrected local_port on linux_user_host_image1**
    
    The local port number given for the mysql connection was 3389 when it should be 3390. This is the port for an SQL injection attack (3389 is for KeepBlue exploit). If you look at the linux_user_host_image2.yaml, you can see this same connection with local_port 3390.  When the exploit KeepBlue happens on User3 (uses linux_user_host_image1), it always fails when it should only succeed, and this is because of this typo. When I fix it, I can see the the SQLInjection succeeds properly, as hoped.
    
    **Initially (~15):**
    
    ```python
      - Connections:
        - local_address: 0.0.0.0
          local_port: 3389
          Transport Protocol: TCP
        PID: 1101
        PPID: 1
        Path: /etc/init.d
        Process Name: mysql
        Username: root
    ```
    
    **Corrected (~15):**
    
    ```python
      - Connections:
        - local_address: 0.0.0.0
          local_port: 3390
          Transport Protocol: TCP
        PID: 1101
        PPID: 1
        Path: /etc/init.d
        Process Name: mysql
        Username: root
    ```
    
5. **Corrected Reward Signal in RedRewardCalculator.py** 

    */CybORG_plus_plus/Debugged_CybORG/CybORG/CybORG/Shared/RedRewardCalculator.py*

    Reward is calculated based on the number of hosts that the red agent has gained access to. These are determined in the function ```PwnRewardCalculator``` by searching for the username root or system depending on the host distribution. However, certain exploits achieve access using different usernames and therefore more/less is assigned based on the exploit method. To correct this requires specififying the additional usernames as shown below:

    **Initially (~52):**
    
    ```python
      if session['Username'] == 'root' and info['System info']['OSType'] == OperatingSystemType.LINUX:
          confidentiality_value = self.mapping[self.scenario.get_host(host).get('ConfidentialityValue', 'Low')]
          root_sessions += confidentiality_value
          self.compromised_hosts[host] = confidentiality_value
          break

      if session['Username'] == 'SYSTEM' and info['System info']['OSType'] == OperatingSystemType.WINDOWS:
          confidentiality_value = self.mapping[self.scenario.get_host(host).get('ConfidentialityValue', 'Low')]
          system_sessions += confidentiality_value
          self.compromised_hosts[host] = confidentiality_value
          break
    ```
    
    **Corrected (~55):**
    
    ```python

      usernames = ['NetworkService', 'vagrant', 'root', 'SYSTEM', 'pi',  'www-data']                       
      if session['Username'] in usernames and info['System info']['OSType'] == OperatingSystemType.LINUX:
          confidentiality_value = self.mapping[self.scenario.get_host(host).get('ConfidentialityValue', 'Low')]
          root_sessions += confidentiality_value
          self.compromised_hosts[host] = confidentiality_value
          break

      if session['Username'] in usernames and info['System info']['OSType'] == OperatingSystemType.WINDOWS:
          confidentiality_value = self.mapping[self.scenario.get_host(host).get('ConfidentialityValue', 'Low')]
          system_sessions += confidentiality_value
          self.compromised_hosts[host] = confidentiality_value
          break  
    ```

6. **Corrected Detection in Blue Observation in BlueTableWrapper.py**

    */CybORG_plus_plus/Debugged_CybORG/CybORG/CybORG/Agents/Wrappers/BlueTableWrapper.py*

    The BlueTableWrapper sometimes incorrectly classifies a host exploit as a scan, which gives rise to a lower detection rate than the specified 95%. The problem arises from the if-else statement in the wrapper and can be corrected by recognising that in CAGE the presence of port 4444 being open always indicates an exploit::

    **Initially (~171):**
    
    ```python
      if num_connections >= 3 and port_focus >=3:
          anomaly = 'Scan'
      elif 4444 in remote_ports:
          anomaly = 'Exploit'
      elif num_connections >= 3 and port_focus == 1:
          anomaly = 'Exploit'
      elif 'Service Name' in activity[0]:
          anomaly = 'None'
      else:
          anomaly = 'Scan'
    ```
    
    **Corrected (~174):**
    
    ```python
      if 4444 in remote_ports:
          anomaly = 'Exploit'
      elif num_connections >= 3 and port_focus >=3:
          anomaly = 'Scan'
      elif num_connections >= 3 and port_focus == 1:
          anomaly = 'Exploit'
      elif 'Service Name' in activity[0]:
          anomaly = 'None'
      else:
          anomaly = 'Scan'
    ```

### Active Bugs

If you identify any further bugs, please do raise an issue or make a pull request highlighting the problem.
