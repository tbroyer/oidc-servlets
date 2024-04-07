package net.ltgt.oidc.servlet.example.jetty;

import org.eclipse.jetty.ee10.servlet.DefaultServlet;
import org.eclipse.jetty.ee10.servlet.ServletContextHandler;
import org.eclipse.jetty.server.Server;

public class Main {
  public static void main(String[] args) throws Exception {
    var server = new Server(Integer.getInteger("example.port", 8000));

    var contextHandler = new ServletContextHandler(ServletContextHandler.SESSIONS);
    contextHandler.setBaseResourceAsString(args[0]);
    server.setHandler(contextHandler);

    contextHandler.addServlet(DefaultServlet.class, "/");

    server.setStopAtShutdown(true);
    server.start();
    server.join();
  }
}
