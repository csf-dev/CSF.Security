//
// PBKDF2Parameters.cs
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
namespace CSF.Security.Authentication
{
  /// <summary>
  /// Implementation of <see cref="IPBKDF2Parameters"/> which carries the appropriate information.
  /// </summary>
  public class PBKDF2Parameters : IPBKDF2Parameters
  {
    /// <summary>
    /// Gets or sets the iteration count.
    /// </summary>
    /// <value>The iteration count.</value>
    public int IterationCount { get; set; }

    /// <summary>
    /// Gets or sets the length of the key (in bytes).
    /// </summary>
    /// <value>The length of the key.</value>
    public int KeyLength { get; set; }

    /// <summary>
    /// Gets or sets the length of the salt (in bytes).
    /// </summary>
    /// <value>The length of the salt.</value>
    public int SaltLength { get; set; }

    int IPBKDF2Parameters.GetKeyLength()
    {
      return KeyLength;
    }

    int IPBKDF2Parameters.GetSaltLength()
    {
      return SaltLength;
    }

    int IPBKDF2Parameters.GetIterationCount()
    {
      return IterationCount;
    }
  }
}
