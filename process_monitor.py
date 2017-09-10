import time
import Crypt
import psutil
import threading
from termcolor import colored

AVG_COUNTER_INIT = 1            #  Memory average initializer
MEM_JUMP_INIT    = 0            #  Memory jump initializer
INT_FLAG         = 1            #  Integer flag for the is_number funtction
FLOAT_FLAG       = 2            #  Float flag for the is_number funtction
JUMP_MULT        = 1.5          #  Memory jump multiplier
BIG_JUMP         = 3            #  Big memory consumption jump approximation helper
MEM_NOTIFIER     = 5            #  Determines when will we start notifying about big memory jumps
INDENT = "\t\t\t\t\t\t\t\t"     #  Indentations for the print

mem_monitor = {}
date_arr    = []
# global remover
remover     = []
log_counter = 1
log         = []


'''
    Removes processes from the dictionary
'''
def remover_proc(remover):
    for tpid in remover:
        try:
            del mem_monitor[tpid]
            # print("{} JUST DIED")
        except KeyError:
            # print("Nevermind")
            pass
    return

'''
    Checks if the input is indeed a number. 1 == int, 2 == float
'''
def is_number(value, type):
    if type == INT_FLAG:
        try:
            int(value)
        except ValueError:
            return False
        return True
    else:
        try:
            float(value)
        except ValueError:
            return False
        return True


'''
    Calculates the average of the process memory percent consumption
    Using the formula: A' = (a_t+1 + t*A)/t+1
'''
def calc_avg(pid, avg, ctr):
    curr_mem = psutil.Process(pid).memory_percent()
    avg = (curr_mem + (ctr - 1) * avg) / ctr
    return avg


'''
  This function generates a dictionary of processes
  It gets its pid, name, memory consumption, and initializes
  the memory consumption average as the current consumption
  and the average counter ('ctr') as 1
'''
def get_proc_dict():

    ans = {}

    for proc in psutil.process_iter():
        try:
            tpid = proc.pid

            ans[tpid] = {}
            ans[tpid]['name'] = proc.name()
            ans[tpid]['mem'] = proc.memory_percent()
            ans[tpid]['avg'] = ans[tpid]['mem']
            ans[tpid]['ctr'] = AVG_COUNTER_INIT
            ans[tpid]['max_jmp'] = MEM_JUMP_INIT
            ans[tpid]['children'] = proc.children(recursive=False)
            ans[tpid]['parent'] = proc.ppid()
            # print (proc.ppid())
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass
    return ans


'''
   This function presents the changes occurred with the
   processes. Prints to the console if monitor mode is
   defined
'''
def get_changes(mon=False):

    try:

        for proc in psutil.process_iter():

            tpid = proc.pid

            if tpid not in mem_monitor:

                if proc.ppid() in mem_monitor and mem_monitor[proc.ppid()]['name'] != "explorer.exe":

                    parent = mem_monitor[proc.ppid()]['name']

                    Crypt.crypt_write("** NEW child process to: Name: {}, PID: {}! Name: {}, PID: {} **\n"
                                      .format(parent, proc.ppid(), proc.name(), tpid), stat_log)
                    # log.append("** NEW process! Name: {}, PID: {} **\n".format(proc.name(), tpid))
                    log.append("** NEW child process to: Name: {}, PID: {}! Name: {}, PID: {} **\n"
                                      .format(parent, proc.ppid(), proc.name(), tpid))

                    if mon:
                        # print(INDENT + "** NEW process! Name: {}, PID: {} **\n".format(proc.name(), tpid))
                        print("** NEW child process to: Name: {}, PID: {}! Name: {}, PID: {} **\n"
                                      .format(parent, proc.ppid(), proc.name(), tpid))

                else:
                    Crypt.crypt_write("++ NEW process! Name: {}, PID: {} ++\n".format(proc.name(), tpid), stat_log)
                    log.append("++ NEW process! Name: {}, PID: {} ++\n".format(proc.name(), tpid))

                    if mon:
                        print(INDENT + "++ NEW process! Name: {}, PID: {} ++\n".format(proc.name(), tpid))

                # Crypt.crypt_write("++ NEW process! Name: {}, PID: {} ++\n".format(proc.name(), tpid), stat_log)
                # log.append("++ NEW process! Name: {}, PID: {} ++\n".format(proc.name(), tpid))
                #
                # if mon:
                #     print(INDENT + "++ NEW process! Name: {}, PID: {} ++\n".format(proc.name(), tpid))

                mem_monitor[tpid] = {}
                mem_monitor[tpid]['name'] = proc.name()
                mem_monitor[tpid]['mem'] = proc.memory_percent()#psutil.Process(tpid).memory_percent()
                mem_monitor[tpid]['avg'] = calc_avg(tpid, mem_monitor[tpid]['mem'], 1)
                mem_monitor[tpid]['ctr'] = 1
                mem_monitor[tpid]['max_jmp'] = 0
                mem_monitor[tpid]['children'] = proc.children(recursive=False)
                mem_monitor[tpid]['parent'] = proc.ppid()

    except KeyError:
        pass
    except psutil.NoSuchProcess:
        print("ADDING TO REMOVER {} {}".format(mem_monitor[tpid]['name'], tpid))
        remover.append(tpid)
        pass

    return


'''
    This function is the file handler.
    If any changes occurred with the processes, it writes it to the file,
    encrypted.
    If monitor mode is defined, the changes will be printed to the console.
    If manual mode is defined, an independent thread will use this function.
    
    This function hashes the files Status_Log.txt and ProcessList.txt before
    and after the timer. If the hash does not match, it prompts to the console
    that the file was modified during runtime.
'''

def file_handling(x_timer, rounds, mon=False):
    global log_counter
    # log_counter = 1

    for i in range(rounds):

        proc_hash_before = Crypt.hash_file("ProcessList.txt")  #  Self explanatory
        log_hash_before = Crypt.hash_file("Status_Log.txt")
        global remover  #  The list of the processes to remove (by PID)
        remover = []

        try:
            arr = get_proc_dict()
            time.sleep(x_timer)

            proc_hash_after = Crypt.hash_file("ProcessList.txt")
            log_hash_after = Crypt.hash_file("Status_Log.txt")

            if proc_hash_before != proc_hash_after:
                print(colored("WARNING! THE FILE ProcessList.txt HAS CHANGED!", 'red'))
                print("The ProcessList.txt file has changed")
            elif log_hash_before != log_hash_after:
                print(colored("WARNING! THE FILE Status_Log.txt HAS CHANGED!", 'red'))
                print("The Status_Log.txt file has changed")

            if mon:
                print(time.strftime("%Y-%m-%d %H:%M"))

            #  Writing dates to the files and to the log

            Crypt.crypt_write('\n\n{})'.format(log_counter), proc_file)
            date_arr.append(time.strftime("%Y-%m-%d %H:%M\n"))
            Crypt.crypt_write(time.strftime("%Y-%m-%d %H:%M\n"), proc_file)
            Crypt.crypt_write('\n{})'.format(log_counter), stat_log)
            Crypt.crypt_write(time.strftime("%Y-%m-%d %H:%M\n"), stat_log)

            log.append('{})'.format(log_counter))
            log.append(time.strftime("%Y-%m-%d %H:%M\n"))

            log_counter += 1

            get_changes(mon)

            for tpid in arr:
                try:

                    if stat_log.closed:
                        return

                    if tpid in mem_monitor:

                        curr_jmp = abs(psutil.Process(tpid).memory_percent() - mem_monitor[tpid]['avg'])

                        #  Checking if the jump was high enough to alert about it
                        if curr_jmp > mem_monitor[tpid]['max_jmp'] * JUMP_MULT:


                            if mem_monitor[tpid]['ctr'] > MEM_NOTIFIER and mem_monitor[tpid]['max_jmp'] != 0:

                                Crypt.crypt_write("Process {}, PID {} is consuming more memory than usual!\n"
                                                  .format(mem_monitor[tpid]['name'], tpid), stat_log)
                                log.append("Process {}, PID {} is consuming more memory than usual!\n"
                                           .format(mem_monitor[tpid]['name'], tpid))
                                if mon:

                                    #  Checking if the jump was too big (maximum jump * 3)
                                    if curr_jmp > mem_monitor[tpid]['max_jmp'] * BIG_JUMP:

                                        print(colored(INDENT + "WARNING! TOO MUCH MEMORY!", 'red'))
                                    else:
                                        print(colored(INDENT + "NOTIFYING!", 'yellow'))
                                    print("Process {}, PID {} is consuming more memory than usual!\n"
                                          .format(mem_monitor[tpid]['name'], tpid))

                            mem_monitor[tpid]['max_jmp'] = curr_jmp * JUMP_MULT

                        mem_monitor[tpid]['avg'] = calc_avg(tpid, mem_monitor[tpid]['avg'], mem_monitor[tpid]['ctr'])
                        mem_monitor[tpid]['ctr'] += 1

                    # else:
                    #     # print("INSIDE ELSE!!!")
                    #
                    #     mem_monitor[tpid] = {}
                    #     mem_monitor[tpid]['name'] = arr[tpid]['name']
                    #     mem_monitor[tpid]['mem'] = psutil.Process(tpid).memory_percent()
                    #     mem_monitor[tpid]['avg'] = calc_avg(tpid, mem_monitor[tpid]['mem'], 1)
                    #     mem_monitor[tpid]['ctr'] = 1
                    #     mem_monitor[tpid]['max_jmp'] = 0


                    Crypt.crypt_write('Name: {0:30} | PID: {1:5} | AVG memory: {2:25} | Biggest jump: {3:25}\n'
                                    .format(mem_monitor[tpid]['name'], tpid, mem_monitor[tpid]['mem'],
                                            mem_monitor[tpid]['max_jmp']), proc_file)

                except psutil.AccessDenied:
                    print("Access denied to process %d!" % tpid)
                except psutil.NoSuchProcess:

                    try:
                        parent_id = mem_monitor[tpid]['parent']
                        parent_name = mem_monitor[parent_id]['name']

                        if parent_id in mem_monitor and mem_monitor[parent_id]['name'] != "explorer.exe":  # Checking if the parent process is in the monitor
                            Crypt.crypt_write(
                                "## A child process just DIED! Name: {}, PID: {}, Parent: Name: {}, PID: {} ##\n"
                                    .format(mem_monitor[tpid]['name'], tpid, parent_name, parent_id), stat_log)
                            log.append(
                                "## A child process just DIED! Name: {}, PID: {}, Parent: Name: {}, PID: {} ##\n"
                                    .format(mem_monitor[tpid]['name'], tpid, parent_name, parent_id))

                            if mon:
                                print(
                                    INDENT + "## A child process just DIED! Name: {}, PID: {}, Parent: Name: {}, PID: {} ##\n"
                                    .format(mem_monitor[tpid]['name'], tpid, parent_name, parent_id))


                        else:
                            Crypt.crypt_write(
                                "-- A process just DIED! Name: {}, PID: {} --\n".format(mem_monitor[tpid]['name'],
                                                                                        tpid),
                                stat_log)
                            log.append(
                                "-- A process just DIED! Name: {}, PID: {} --\n".format(mem_monitor[tpid]['name'],
                                                                                        tpid))

                            if mon:
                                print(
                                    INDENT + "-- A process just DIED! Name: {}, PID: {} --\n".format(
                                        mem_monitor[tpid]['name'], tpid))

                        remover.append(tpid)

                    except KeyError:
                    #     print("KeyError 328 with process {}. key = {}".format(tpid, tpid))
                        pass


                except (ValueError, KeyError):
                    pass


                remover_proc(remover)
                remover = []
        except IOError:
            print("Thread ended, I/O")
            return date_arr

    if mon:
        next_move = raw_input("Continue? y for Yes, anything else for No: \t")
        if str(next_move) == 'y':
            main()
            return

    # stat_log.close()
    return date_arr

'''
    The main function.
    Asks for a timer for the sampling and the number of rounds (i.e samples).
'''
def main():

    while True:
        x_timer = raw_input("Enter the X timer: ")
        rounds = raw_input("Enter number of rounds: ")
        if not is_number(x_timer, FLOAT_FLAG) or not is_number(rounds, INT_FLAG):
            print("Invalid input!")
            continue
        else:
            x_timer = float(x_timer)
            rounds = int(rounds)
            print("Check every %f seconds %d times" % (x_timer, rounds))
            break

    mon = False

    #  The menu:
    #  ---------

    while True:
        print("\n\nChoose the mode:\n1)Monitoring mode. Prints to the console.\n"
              "2)Manual. Choosing dates to see changes.\nq) Quit\n")
        mode = raw_input("Your choice: ")
        mode = str(mode)
        if mode != 'q' and mode != '1' and mode != '2':
            print("Invalid input! Try again!")
            continue
        elif mode == '1':
            mon = True
            print(INDENT + "-------Starting monitor mode-------")
            break
        elif mode == '2':
            print(INDENT + "-------Starting manual mode-------")
            break
        else:
            print("\nYou didn't even do anything!\nNevermind, byebye.")
            return

    activate_thread = True
    t = threading.Thread(target=file_handling, args=(x_timer, rounds,))

    while mode != 'q':

        if not mon:
            if activate_thread:
                activate_thread = False
                t.start()
            print("-----------------------------------------------------------------")
            print("Choose 2 dates to declare the range, f for refresh, or q in one of them to quit:\n")
            for i in range(len(date_arr)):
                print('{0}) {1}'.format(i + 1, date_arr[i]))

            print("-----------------------------------------------------------------\n\n")
            first = raw_input("First: ")

            if not first.isdigit():
                if first != 'q' and first != 'f':
                    print("Invalid input!")
                    continue
                elif first == 'f':
                    continue
                else:
                    print("Hope you had fun. Goodbye!\n")
                    break

            second = raw_input("Second: ")

            if not first.isdigit() or not second.isdigit():
                if first != 'q' and not first.isdigit():
                    print("Invalid input!")
                    continue
                elif second != 'q' and not second.isdigit():
                    print("Invalid input!")
                    continue
                else:
                    print("Hope you had fun. Goodbye!")
                    break

            first = int(first)
            second = int(second)
            print("You chose: {}, {}".format(first, second))
            print("-----------------------------------------------------------------\n\n")

            #  Swap if needed
            if first > second:
                t = first
                first = second
                second = t

            flag = False

            for line in log:

                if line[0:2] == '{})'.format(first):
                    flag = True

                if flag:
                    if line[0:2] == '{})'.format(second + 1):
                        break
                    else:
                        print(line)

        else:
            file_handling(x_timer, rounds, mon)
            break

    if not mon:
        next_move = raw_input("\nHold on. Maybe continue? y for Yes, anything else for No: \t")
        if str(next_move) == 'y':
            main()
            return
        else:
            print("Byebye!")

    proc_file.write("{}".format(Crypt.rand))
    stat_log.close()
    proc_file.close()

    return 0


if __name__ == '__main__':

    proc_file = open("ProcessList.txt", "w")
    proc_file.close()
    stat_log = open("Status_Log.txt", "w")
    stat_log.close()

    proc_file = open("ProcessList.txt", "r+")
    stat_log = open("Status_Log.txt", "r+")

    mem_monitor = get_proc_dict()

    main()

    Crypt.decrypt_file("Status_Log.txt")
    Crypt.decrypt_file("ProcessList.txt")
