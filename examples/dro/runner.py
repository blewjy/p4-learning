import threading
import time

class ThreadWorker(threading.Thread):
    def __init__(self, callable, *args, **kwargs):
        super(ThreadWorker, self).__init__()
        self.callable = callable
        self.args = args
        self.kwargs = kwargs
        self.setDaemon(True)

    def run(self):
        try:
            self.callable(*self.args, **self.kwargs)
        except wx.PyDeadObjectError:
            pass
        except Exception, e:
            print e

if __name__ == "__main__":

    import os
    from subprocess import Popen, PIPE

    results = []
    count = 1
    total_runs = 1

    print "Starting the test for a total of", total_runs, "runs.\n"

    while len(results) < total_runs:

	    print "** START: Round {} **".format(count)

	    def worker(pipe):
	    	done = False
	        while True:
	            line = pipe.readline()
	            if line == '': break
	            else: 
	            	if "pro-debug" in line:
	            		print line
	            		
	            	if "pro-debug" in line and "s4" in line:
	            		arr = line.replace("["," ").replace("]", " ").replace(","," ").split()
	            		results.append((int(arr[-1]) - int(arr[-2]))/1000.0)

	    proc = Popen("sudo p4run --config fat-tree-topo/p4app.json", shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE)

	    stdout_worker = ThreadWorker(worker, proc.stdout)
	    stderr_worker = ThreadWorker(worker, proc.stderr)
	    stdout_worker.start()
	    stderr_worker.start()
	    
	    while proc.poll() is None:
	    	time.sleep(10)
	    	print ".",

	    print "\nResult:", results[-1], "ms"
	    if results[-1] < 0:
	    	print "FAIL! Negative result. This run is voided."
	    	del results[-1]
	    print "*** END: Round {} ***\n".format(count)
	    count += 1

    print ""
    print "hehe all done"
    print "final results:", results
    print "avg:", sum(results)/len(results)