package net.ltgt.oidc.servlet.example.jetty;

import static java.util.Objects.requireNonNull;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;
import java.io.IOException;
import java.util.Objects;

public class SpaFilter extends HttpFilter {

  public static final String FORWARD_PATH = "forward-path";
  public static final String DEFAULT_SERVLET_NAME = "default-servlet-name";

  private String forwardPath;
  private String defaultServletName;

  @Override
  public void init() throws ServletException {
    forwardPath = requireNonNull(getInitParameter(FORWARD_PATH));
    defaultServletName = requireNonNull(getInitParameter(DEFAULT_SERVLET_NAME));
  }

  @Override
  protected void doFilter(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
      throws IOException, ServletException {
    if (!Objects.equals(defaultServletName, req.getHttpServletMapping().getServletName())) {
      chain.doFilter(req, res);
      return;
    }
    var response = new NotFoundCatcherResponse(res);
    chain.doFilter(req, response);
    if (response.error) {
      res.setHeader("Content-Location", forwardPath);
      req.getRequestDispatcher(forwardPath).forward(req, res);
    }
  }

  private static class NotFoundCatcherResponse extends HttpServletResponseWrapper {
    boolean error;

    public NotFoundCatcherResponse(HttpServletResponse res) {
      super(res);
    }

    @Override
    public void sendError(int sc) throws IOException {
      if (sc == SC_NOT_FOUND) {
        if (isCommitted()) {
          throw new IllegalStateException("Committed");
        }
        error = true;
      } else {
        super.sendError(sc);
      }
    }

    @Override
    public void sendError(int sc, String msg) throws IOException {
      if (sc == SC_NOT_FOUND) {
        if (isCommitted()) {
          throw new IllegalStateException("Committed");
        }
        error = true;
      } else {
        super.sendError(sc);
      }
    }
  }
}
