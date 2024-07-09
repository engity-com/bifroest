package main

import "C"

//
//func registerTestFlowCmd(app *kingpin.Application) {
//	cmd := app.Command("test-flow", "Used to test the flow on command line without PAM").
//		Action(func(*kingpin.ParseContext) error {
//			return doTestFlow()
//		})
//	cmd.Arg("configuration", "Configuration which should be used to test the flow.").
//		Required().
//		SetValue(&configurationRef)
//	cmd.Arg("username", "Username which should be used as requested.").
//		Required().
//		StringVar(&requestedUsername)
//	cmd.Arg("socket", "Socket where the service is bound to.").
//		Default(socketPath).
//		StringVar(&socketPath)
//}
//
//func doTestFlow() error {
//	fail := func(err error) error {
//		log.Error(err)
//		return err
//	}
//	failf := func(message string, args ...any) error {
//		return fail(fmt.Errorf(message, args...))
//	}
//
//	address := syscall.SockaddrUnix{
//		Name: socketPath,
//	}
//	sockfd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
//	if err != nil {
//		return failf("cannot create socket: %w", err)
//	}
//
//	if err := syscall.Connect(sockfd, &address); err != nil {
//		return failf("cannot connect socket: %w", err)
//	}
//	defer func() {
//		_ = syscall.Close(sockfd)
//	}()
//
//	if _, err = syscall.Write(sockfd, []byte("foo")); err != nil {
//		return failf("cannot write: %w", err)
//	}
//
//	buf := make([]byte, 1024)
//	if n, err := syscall.Read(sockfd, buf); err != nil {
//		return failf("cannot read: %w", err)
//	} else {
//		log.With("data", string(buf[:n])).Info("message received from server")
//	}
//
//	return nil
//
//	cr := rpc.CliToPamSoCallReceiver{
//		OnSyslog: func(priority syslog.Priority, message string) error {
//			var lf func(...any)
//
//			switch priority {
//			case syslog.LOG_EMERG, syslog.LOG_ALERT, syslog.LOG_CRIT:
//				lf = log.Info
//			case syslog.LOG_WARNING:
//				lf = log.Warn
//			case syslog.LOG_DEBUG:
//				lf = log.Debug
//			default:
//				lf = log.Info
//			}
//
//			lf(message)
//			return nil
//		},
//
//		OnInfo: func(message string) error {
//			log.Info(message)
//			return nil
//		},
//
//		OnSuccessResult: func(ipr pam.Result, localUser string, localUid uint64, localGroup string, localGid uint64) error {
//			log.Infof("remote user %q was successfully authorized as local user %d(%s):%d(%s)", requestedUsername, localUid, localUser, localGid, localGroup)
//			return nil
//		},
//
//		OnFailedResult: func(ipr pam.Result, pect pam.ErrorCauseType, message string) error {
//			return ipr.Errorf(pam.ErrorCauseTypeUser, message)
//		},
//	}
//
//	pR, pW, err := os.Pipe()
//	if err != nil {
//		return fail(err)
//	}
//	defer func() {
//		_ = pR.Close()
//	}()
//	defer func() {
//		_ = pW.Close()
//	}()
//
//	prc, err := os.StartProcess(os.Args[0], []string{os.Args[0], "internal-flow", configurationRef.GetFilename(), requestedUsername}, &os.ProcAttr{
//		Files: []*os.File{os.Stdin, pW, os.Stderr},
//		Env:   os.Environ(),
//	})
//	if err != nil {
//		return fail(fmt.Errorf("cannot start %q: %w", os.Args[0], err))
//	}
//	defer func() { _ = prc.Kill() }()
//
//	pr, err := cr.Run(pR)
//	if err != nil {
//		return fail(err)
//	}
//
//	if _, err := prc.Wait(); err != nil {
//		return fail(fmt.Errorf("the cli %q was not successful: %w", os.Args[0], err))
//	}
//
//	log.Infof("process ended with %v", pr)
//
//	return nil
//}
