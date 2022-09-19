External Libraries Used

dnspython
cryptography


Instructions to Run the Program

Part A

1) Open the command prompt and go to the directory where the python files are present

2) Type the following - 
    python mydig.py 

3) It will ask for the domain name as follows - 
    Enter the name of the domain you want to resolve

4) Type in the domain name as follows - 
    cnn.com

5) It will ask for the resolution type as follows -
    Enter type of DNS resolution -> A, NS or MX

6) Type in the resolution type as follows -
    A 

7) You will be able to see the output as follows - 
    QUESTION SECTION:

    cnn.com   IN  A

    ANSWER SECTION:

    cnn.com IN A  151.101.67.5

    Query Time: 80.3316 msec

    WHEN: Mon Sep 19 19:30:08 2022

    MSG SIZE rcvd: 88

Part B

1) Open the command prompt and go to the directory where the python files are present

2) Type the following - 
    python dnssec.py 

3) It will ask for the domain name as follows - 
    Enter the name of the domain you want to resolve

4) Type in the domain name as follows - 
    verisigninc.com

7) You will be able to see the output as follows -
    QUESTION SECTION:

    verisigninc.com   IN  A

    ANSWER SECTION:

    verisigninc.com IN A  69.58.187.40

    Query Time: 270.1116 msec

    WHEN: Mon Sep 19 19:43:20 2022

    MSG SIZE rcvd: 88