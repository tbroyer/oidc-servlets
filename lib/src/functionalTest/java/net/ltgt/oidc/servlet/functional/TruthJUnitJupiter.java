package net.ltgt.oidc.servlet.functional;

import com.google.common.truth.StandardSubjectBuilder;
import org.opentest4j.TestAbortedException;

// This is a copy of TruthJUnit adapted for JUnit Jupiter
public final class TruthJUnitJupiter {
  @SuppressWarnings("ConstantCaseForConstants") // Despite the "Builder" name, it's not mutable.
  private static final StandardSubjectBuilder ASSUME =
      StandardSubjectBuilder.forCustomFailureStrategy(
          failure -> {
            var testAborted = new TestAbortedException(failure.getMessage(), failure.getCause());
            testAborted.setStackTrace(failure.getStackTrace());
            throw testAborted;
          });

  /**
   * Begins a call chain with the fluent Truth API. If the check made by the chain fails, it will
   * throw {@link TestAbortedException}.
   */
  public static StandardSubjectBuilder assume() {
    return ASSUME;
  }

  private TruthJUnitJupiter() {}
}
