using System;
using System.Text.RegularExpressions;

namespace SecurityToolkit.Tools
{
    public class PasswordStrengthChecker
    {
        public enum StrengthLevel
        {
            VeryWeak,
            Weak,
            Fair,
            Good,
            Strong,
            VeryStrong
        }

        public void CheckPassword(string password)
        {
            if (string.IsNullOrEmpty(password))
            {
                Console.WriteLine("비밀번호를 입력해주세요.");
                return;
            }

            var strength = EvaluateStrength(password);
            DisplayResult(password, strength);
        }

        private StrengthLevel EvaluateStrength(string password)
        {
            int score = 0;

            // 길이 검사
            if (password.Length >= 8) score += 1;
            if (password.Length >= 12) score += 1;
            if (password.Length >= 16) score += 1;

            // 문자 종류 검사
            if (Regex.IsMatch(password, "[a-z]")) score += 1;
            if (Regex.IsMatch(password, "[A-Z]")) score += 1;
            if (Regex.IsMatch(password, "[0-9]")) score += 1;
            if (Regex.IsMatch(password, "[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>?]")) score += 1;

            // 연속 문자 검사
            if (!HasConsecutiveCharacters(password)) score += 1;
            if (!HasRepeatedCharacters(password)) score += 1;

            return score switch
            {
                <= 2 => StrengthLevel.VeryWeak,
                <= 3 => StrengthLevel.Weak,
                <= 4 => StrengthLevel.Fair,
                <= 6 => StrengthLevel.Good,
                <= 8 => StrengthLevel.Strong,
                _ => StrengthLevel.VeryStrong
            };
        }

        private bool HasConsecutiveCharacters(string password)
        {
            for (int i = 0; i < password.Length - 2; i++)
            {
                if (password[i] + 1 == password[i + 1] && password[i + 1] + 1 == password[i + 2])
                    return true;
            }
            return false;
        }

        private bool HasRepeatedCharacters(string password)
        {
            for (int i = 0; i < password.Length - 2; i++)
            {
                if (password[i] == password[i + 1] && password[i + 1] == password[i + 2])
                    return true;
            }
            return false;
        }

        private void DisplayResult(string password, StrengthLevel strength)
        {
            string display = new string('*', password.Length);
            Console.WriteLine($"비밀번호: {display}");
            Console.WriteLine($"길이: {password.Length}자");

            string strengthText = strength switch
            {
                StrengthLevel.VeryWeak => "매우 약함 ✗",
                StrengthLevel.Weak => "약함 ✗",
                StrengthLevel.Fair => "보통 ⚠",
                StrengthLevel.Good => "좋음 ✓",
                StrengthLevel.Strong => "강함 ✓✓",
                StrengthLevel.VeryStrong => "매우 강함 ✓✓✓",
                _ => "알 수 없음"
            };

            Console.WriteLine($"강도: {strengthText}\n");

            if (strength < StrengthLevel.Good)
            {
                Console.WriteLine("권장사항:");
                if (password.Length < 12) Console.WriteLine("  - 최소 12자 이상 사용");
                if (!Regex.IsMatch(password, "[A-Z]")) Console.WriteLine("  - 대문자 포함");
                if (!Regex.IsMatch(password, "[0-9]")) Console.WriteLine("  - 숫자 포함");
                if (!Regex.IsMatch(password, "[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>?]")) Console.WriteLine("  - 특수문자 포함");
                Console.WriteLine();
            }
        }
    }
}
