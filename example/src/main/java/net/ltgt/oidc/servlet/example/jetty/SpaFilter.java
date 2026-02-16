/*
 * Copyright © 2026 Thomas Broyer
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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

    NotFoundCatcherResponse(HttpServletResponse res) {
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
