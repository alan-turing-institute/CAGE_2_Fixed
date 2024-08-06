# CAGE Challenge 2 debugged

Another Cage 2 repo with a few fixes:

### Bug Fixes

1. **Fixed issue with 'Remove' action**: 
    
    *cage-challenge-2/CybORG/CybORG/Shared/Actions/AbstractActions/Remove.py*
    
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
    
    *cage-challenge-2/CybORG/CybORG/Shared/Actions/ConcreteActions/DecoyVsftpd.py*
    
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
    
    *cage-challenge-2/CybORG/CybORG/Shared/Scenarios/images/Internal_image.yaml*
    
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
    

1. **Corrected local_port on linux_user_host_image1**
    
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
    

1. **More to add…?**
