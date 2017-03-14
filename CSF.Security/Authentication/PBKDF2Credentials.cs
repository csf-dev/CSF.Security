//
// PBKDF2Credentials.cs
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
  public class PBKDF2Credentials : IPBKDF2Credentials
  {
    public string Key { get; set; }

    public string Salt { get; set; }

    public int IterationCount { get; set; }

    private byte[] GetKeyAsByteArray()
    {
      if(Key == null)
      {
        return null;
      }

      return Convert.FromBase64String(Key);
    }

    private byte[] GetSaltAsByteArray()
    {
      if(Salt == null)
      {
        return null;
      }

      return Convert.FromBase64String(Salt);
    }

    int IPBKDF2Parameters.GetIterationCount()
    {
      return IterationCount;
    }

    byte[] IPBKDF2Credentials.GetKeyAsByteArray()
    {
      return GetKeyAsByteArray();
    }

    int IPBKDF2Parameters.GetKeyLength()
    {
      var key = GetKeyAsByteArray();
      return (key != null)? key.Length : 0;
    }

    byte[] IPBKDF2Credentials.GetSaltAsByteArray()
    {
      return GetSaltAsByteArray();
    }

    int IPBKDF2Parameters.GetSaltLength()
    {
      var salt = GetSaltAsByteArray();
      return (salt != null)? salt.Length : 0;
    }
  }
}
