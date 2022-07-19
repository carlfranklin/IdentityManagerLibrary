using System.Collections.Generic;
using Microsoft.AspNetCore.Identity;

namespace IdentityManagerLibrary
{
    public static class Extensions
    {
        /// <summary>
        /// Extension method that takes a collection of IEnumerable<IdentityError> and 
        /// concatenates all error descriptions into a string.
        /// </summary>
        /// <param name="errors">Collection of IdentityError objects.</param>
        /// <returns>A string containing all error messages in the collection.</returns>
        public static string GetAllMessages(this IEnumerable<IdentityError> errors)
        {
            var result = string.Empty;

            if (errors == null)
                return result;

            foreach (var error in errors)
            {
                result += string.IsNullOrEmpty(result) ? string.Empty : " ";
                result += error.Description;
            }

            return result;
        }
    }
}