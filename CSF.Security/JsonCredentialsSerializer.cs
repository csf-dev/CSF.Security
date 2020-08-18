//
// JsonCredentialsSerializer.cs
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
using System.IO;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;
using Newtonsoft.Json;

namespace CSF.Security.Authentication
{
    /// <summary>
    /// Implementation of <see cref="ICredentialsSerializer"/> which serializes/deserializes to/from JSON-formatted
    /// strings.
    /// </summary>
    public class JsonCredentialsSerializer : ICredentialsSerializer
    {
        static readonly Regex credentialsWithTypeName = new Regex(@"^\s*\{");

        #region Deserialization

        /// <summary>
        /// Deserialize the specified serialized credentials string.
        /// </summary>
        /// <param name="credentials">Credentials.</param>
        public object Deserialize(string credentials)
        {
            if (credentials == null)
                throw new ArgumentNullException(nameof(credentials));

            var typeAndJson = GetTypeAndJson(credentials);
            return Deserialize(typeAndJson.Item2, typeAndJson.Item1);
        }

        (Type, string) GetTypeAndJson(string credentials)
        {
            var isCredentialsWithTypeName = credentialsWithTypeName.IsMatch(credentials);
            if (isCredentialsWithTypeName) return (null, credentials);

            var parts = credentials.Split(new[] { ':' }, 2);
            if (parts.Length != 2)
                throw new FormatException("Credentials string must contain a type name, followed by a colon and then a JSON-formatted serialized object.");

            var typeName = parts[0];
            var json = parts[1];

            return (Type.GetType(typeName), json);
        }

        object Deserialize(string json, Type type)
        {
            var serializer = JsonSerializer.CreateDefault();
            serializer.TypeNameHandling = (type == null) ? TypeNameHandling.Auto : TypeNameHandling.None;

            using (var reader = new StringReader(json))
                return serializer.Deserialize(reader, type ?? typeof(object));
        }

        #endregion

        #region Serialization

        /// <summary>
        /// Serialize the specified credentials to a string.
        /// </summary>
        /// <param name="credentials">Credentials.</param>
        /// <typeparam name="TCredentials">The 1st type parameter.</typeparam>
        public string Serialize<TCredentials>(TCredentials credentials)
        {
            if (ReferenceEquals(credentials, null))
                throw new ArgumentNullException(nameof(credentials));

            var serializer = JsonSerializer.CreateDefault();
            serializer.TypeNameHandling = TypeNameHandling.Objects;

            var output = new StringBuilder();

            using (var writer = new StringWriter(output))
            {
                serializer.Serialize(writer, credentials);
                writer.Flush();
            }

            return output.ToString();
        }

        #endregion
    }
}
