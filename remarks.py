
# counter = 1;

# for i in range(rounds):
#     arr = get_proc_arr()
#     time.sleep(x_timer)
#     print(time.strftime("%Y-%m-%d %H:%M"))
#
#     proc_file.write('\n\n{})'.format(counter))
#     proc_file.write(time.strftime("%Y-%m-%d %H:%M\n"))
#     stat_log.write('\n\n{})'.format(counter))
#     stat_log.write(time.strftime("%Y-%m-%d %H:%M\n"))
#     counter += 1
#
#     print(get_changes(arr))
#     for proc in arr:
#         try:
#
#             curr_jmp = abs(proc.usg() - proc.get_avg())
#             if curr_jmp > proc.get_max_jmp() and proc.monitoring():
#                 print("Process %s is acting wierd!")
#
#             if proc.pid() in mem_monitor:
#                 curr_jmp = mem_monitor[proc.pid()][3]
#             else:
#                 curr_jmp = 0
#             mem_monitor[proc.pid()] = [proc.name(), proc.usg(), proc.calc_avg(),
#                                        max(abs(proc.usg() - proc.get_avg()), curr_jmp)]
#                                        # proc.max_jmp(abs(proc.usg() - proc.get_avg()))]
#             proc.calc_avg()
#             # print(mem_monitor[proc.pid()])
#
#
#
#             # proc_file.write("Name: %s, PID: %d, AVG memory: %.4f, Biggest jump: %f\n"
#             #                 % (proc.name(), proc.pid(), proc.usg(), mem_monitor[proc.pid()][3]))
#
#             proc_file.write('Name: {0:30} | PID: {1:5} | AVG memory: {2:25} | Biggest jump: {3:25}\n'
#                             .format(proc.name(), proc.pid(), proc.usg(), mem_monitor[proc.pid()][3]))
#                             # % (proc.name(), proc.pid(), proc.usg(), mem_monitor[proc.pid()][3]))
#
#         except (psutil.AccessDenied, psutil.NoSuchProcess):
#             print ("Process %d not found or access denied!" % proc.pid())