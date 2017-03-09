//
// PBKDF2CredentialVerifier2.cs
//
// Author:
//       Craig Fowler <craig@csf-dev.com>
//
// Copyright (c) 2017 Craig Fowler
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
using System;
namespace CSF.Security
{
  /// <summary>
  /// Generic implementation of <see cref="PBKDF2CredentialVerifier"/>.
  /// </summary>
  [Obsolete("Instead, use the non-generic implementation.")]
  public class PBKDF2CredentialVerifier<TEntered,TStored> : PBKDF2CredentialVerifier
    where TEntered : ICredentialsWithPassword
    where TStored : IStoredCredentialsWithKeyAndSalt
  {
    /// <summary>
    /// Initializes a new instance of the <see cref="PBKDF2CredentialVerifier"/> class.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The iteration count is the "work factor" indicating how difficult it is to perform the hashing operation.
    /// As of 2012, a sane starting point I have seen suggests 64000 iterations.  This should double roughly every
    /// two years (thus 256k as of 2016).
    /// </para>
    /// <para>
    /// This however is only really a starting point.  It is important to measure the performance on your own hardware
    /// and also consider performance on a "password cracking machine" (loaded with GPUs and the like).  You are aiming
    /// for it to take as long as is acceptable on your own hardware (10ms or so for a multi-user network/web service
    /// seems reasonable) and also to take a long as possible on the reference "cracking machine".
    /// </para>
    /// <para>
    /// The aim is to ensure that you have acceptable performance for logins on your own hardware, but that crackers
    /// wouldn't be able to try thousands/millions of passwords every second if they compromised your database.
    /// </para>
    /// </remarks>
    /// <param name="iterationCount">Iteration count.</param>
    public PBKDF2CredentialVerifier(int iterationCount = DefaultIterationCount) : base(iterationCount) {}

    /// <summary>
    /// Initializes a new instance of the <see cref="PBKDF2CredentialVerifier"/> class.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This overload of the constructor initialises the instance from the entered and stored credentials.
    /// </para>
    /// </remarks>
    /// <param name="enteredCredentials">Entered credentials.</param>
    /// <param name="storedCredentials">Stored credentials.</param>
    public PBKDF2CredentialVerifier(TEntered enteredCredentials,
                                    TStored storedCredentials) : base(enteredCredentials, storedCredentials) {}
  }
}
