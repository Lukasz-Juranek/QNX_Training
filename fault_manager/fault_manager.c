#include <errno.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/iofunc.h>
#include <sys/dispatch.h>
#include <sys/resmgr.h>
#include <time.h>
#include <sys/slog2.h>

static resmgr_connect_funcs_t connect_funcs;
static resmgr_io_funcs_t io_funcs;
static iofunc_attr_t attr;
static char *fault_mgr_status = "Fault manager works ok\n";

static slog2_buffer_t buffer_handle[1];
static slog2_buffer_set_config_t buffer_config;
int fault_pulse_number = 15;

/*Application logic, Saves time and fault number  to file */
int log_fault(int fault_number) {
	// Open file with flags to create if not exists, and append
	int fd = open("/data/fault_log", O_CREAT | O_WRONLY | O_APPEND, 0644);
	if (fd == -1) {
		perror("Failed to open/create log file");
		return -1;
	}

	// Get current time
	time_t current_time;
	struct tm *time_info;

	time(&current_time);
	time_info = localtime(&current_time);

	// Format time as string (YYYY-MM-DD HH:MM:SS)
	char timestamp[64];
	strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", time_info);

	// Create log entry
	char log_entry[128];
	int entry_length = snprintf(log_entry, sizeof(log_entry), "%s %d\n",
			timestamp, fault_number);

	// Write to file
	ssize_t bytes_written = write(fd, log_entry, entry_length);

	// Close file
	close(fd);

	if (bytes_written == -1) {
		perror("Failed to write to log file");
		return -1;
	}

	return 0;
}

/* POSIX WRITE handler */
int io_write(resmgr_context_t *ctp, io_write_t *msg, RESMGR_OCB_T *ocb) {
	int status;
	char *buf;
	size_t nbytes;

	if ((status = iofunc_write_verify(ctp, msg, ocb, NULL)) != EOK)
		return (status);

	if ((msg->i.xtype & _IO_XTYPE_MASK) != _IO_XTYPE_NONE)
		return (ENOSYS);

	/* Extract the length of the client's message. */
	nbytes = _IO_WRITE_GET_NBYTES(msg);

	/* Filter out malicious write requests that attempt to write more
	 data than they provide in the message. */
	if (nbytes
			> (size_t) ctp->info.srcmsglen - (size_t) ctp->offset
					- sizeof(io_write_t)) {
		return EBADMSG;
	}

	/* set up the number of bytes (returned by client's write()) */
	_IO_SET_WRITE_NBYTES(ctp, nbytes);

	buf = (char*) malloc(nbytes + 1);
	if (buf == NULL)
		return (ENOMEM);

	/*
	 *  Read the data from the sender's message.
	 *  We're not assuming that all of the data fit into the
	 *  resource manager library's receive buffer.
	 */
	resmgr_msgget(ctp, buf, nbytes, sizeof(msg->i));
	buf[nbytes] = '\0'; /* just in case the text is not NULL terminated */
	printf("Received %zu bytes = '%s'\n", nbytes, buf);

	int fault_no = strtol(buf, 0, 10);
	slog2f(buffer_handle[0], 0, SLOG2_INFO, "write call %i", fault_no);
	log_fault(fault_no);

	free(buf);

	if (nbytes > 0)
		ocb->attr->flags |= IOFUNC_ATTR_MTIME | IOFUNC_ATTR_CTIME;

	return (_RESMGR_NPARTS(0));
}

/* POSIX read hanlder*/
int io_read(resmgr_context_t *ctp, io_read_t *msg, RESMGR_OCB_T *ocb) {
	size_t nleft;
	size_t nbytes;
	int nparts;
	int status;

	if ((status = iofunc_read_verify(ctp, msg, ocb, NULL)) != EOK)
		return (status);

	if ((msg->i.xtype & _IO_XTYPE_MASK) != _IO_XTYPE_NONE)
		return (ENOSYS);

	/*
	 *  On all reads (first and subsequent), calculate how many bytes we can
	 *  return to the client, based upon the number of bytes available (nleft)
	 *  and the client's buffer size
	 */
	nleft = ocb->attr->nbytes - ocb->offset;
	nbytes = min(_IO_READ_GET_NBYTES(msg), nleft);

	if (nbytes > 0) {
		/* set up the return data IOV */
		SETIOV(ctp->iov, fault_mgr_status + ocb->offset, nbytes);

		/* set up the number of bytes (returned by client's read()) */
		_IO_SET_READ_NBYTES(ctp, nbytes);

		/*
		 * advance the offset by the number of bytes returned to the client
		 */
		ocb->offset += nbytes;

		nparts = 1;
	} else {
		/*
		 * they've asked for zero bytes or they've already previously
		 * read everything
		 */
		_IO_SET_READ_NBYTES(ctp, 0);

		nparts = 0;
	}

	/* mark the access time as invalid (we just accessed it) */
	if (msg->i.nbytes > 0)
		ocb->attr->flags |= IOFUNC_ATTR_ATIME;

	return (_RESMGR_NPARTS(nparts));
}

int fault_pulse_handler(message_context_t *ctp, int code, unsigned flags,
		void *handle) {

	slog2f(buffer_handle[0], 0, SLOG2_INFO, "pulse received code: %i fault: %i",
			code, ctp->msg->pulse.value.sival_int);
	if (code == fault_pulse_number)
		log_fault(ctp->msg->pulse.value.sival_int);
	return 0;

}

int main(int argc, char **argv) {

	buffer_config.buffer_set_name = "fault_manager";
	buffer_config.num_buffers = 1;
	buffer_config.verbosity_level = SLOG2_INFO;
	buffer_config.buffer_config[0].buffer_name = "main";
	buffer_config.buffer_config[0].num_pages = 1;

	if (-1 == slog2_register(&buffer_config, buffer_handle, 0)) {
		fprintf( stderr, "Error registering slogger2 buffer!\n");
		return -1;
	}

	slog2f(buffer_handle[0], 0, SLOG2_INFO, "init");

	/* declare variables we'll be using */
	resmgr_attr_t resmgr_attr;
	dispatch_t *dpp;
	dispatch_context_t *ctp;
	int id;

	/* initialize dispatch interface */
	dpp = dispatch_create_channel(-1, DISPATCH_FLAG_NOLOCK);
	if (dpp == NULL) {
		fprintf(stderr, "%s: Unable to allocate dispatch handle.\n", argv[0]);
		return EXIT_FAILURE;
	}

	/* initialize resource manager attributes */
	memset(&resmgr_attr, 0, sizeof resmgr_attr);
	resmgr_attr.nparts_max = 1;
	resmgr_attr.msg_max_size = 2048;

	/* functions for handling messages */
	iofunc_func_init(_RESMGR_CONNECT_NFUNCS, &connect_funcs,
	_RESMGR_IO_NFUNCS, &io_funcs);

	io_funcs.read = io_read;
	connect_funcs.open = iofunc_open_default;
	io_funcs.write = io_write;

	/* initialize attribute structure used by the device */
	iofunc_attr_init(&attr, S_IFNAM | 0666, 0, 0);
	attr.nbytes = strlen(fault_mgr_status) + 1;

	/* attach our device name */
	id = resmgr_attach(dpp, /* dispatch handle        */
		&resmgr_attr, /* resource manager attrs */
		"/dev/fault_manager", /* device name            */
		_FTYPE_ANY, /* open type              */
		0, /* flags                  */
		&connect_funcs, /* connect routines       */
		&io_funcs, /* I/O routines           */
		&attr); /* handle                 */

	if (id == -1) {
		fprintf(stderr, "%s: Unable to attach name.\n", argv[0]);
		return EXIT_FAILURE;
	}

	if (pulse_attach(dpp, 0, fault_pulse_number, &fault_pulse_handler, NULL) == -1) {
		fprintf( stderr, "Failed to attach code %d.\n", fault_pulse_number);
		return EXIT_FAILURE;
	}

	slog2c(buffer_handle[0], 0, SLOG2_INFO, "start");
	printf("Start \n");
	/* allocate a context structure */
	ctp = dispatch_context_alloc(dpp);

	/* start the resource manager message loop */
	while (1) {
		if ((ctp = dispatch_block(ctp)) == NULL) {
			fprintf(stderr, "block error\n");
			return EXIT_FAILURE;
		}
		dispatch_handler(ctp);
	}
	return EXIT_SUCCESS;
}
