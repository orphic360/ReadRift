from google.generativeai import configure, GenerativeModel
import nltk
from nltk.tokenize import sent_tokenize
nltk.download('punkt')

class BookAnalyzer:
    def __init__(self, book_path):
        self.book_path = book_path
        self.book_text = self._load_book()
        
        # Configure Gemini API
        configure(api_key="AIzaSyBOIMAxbRULe4sN3dOPfpXBWWuA_Jz5xLI")
        self.model = GenerativeModel('gemini-2.0-flash')
        
        # Tokenize sentences
        self.sentences = self._tokenize_sentences(self.book_text)

    def _load_book(self):
        try:
            with open(self.book_path, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception as e:
            print(f"Error loading book: {e}")
            return "No book text available"

    def _tokenize_sentences(self, text):
        try:
            return sent_tokenize(text)
        except Exception as e:
            print(f"Error tokenizing sentences: {e}")
            return []

    def get_definition(self, word):
        try:
            response = self.model.generate_content(
                f"Define the word '{word}' in a clear and concise way. "
                f"Include its part of speech and common usage."
            )
            return str(response.text)
        except Exception as e:
            print(f"Error getting definition: {str(e)}")
            return f"Definition not available for '{word}'"

    def get_synonyms(self, word):
        try:
            response = self.model.generate_content(
                f"List 5-10 synonyms for the word '{word}'. "
                f"Include their meanings and usage examples."
            )
            return str(response.text)
        except Exception as e:
            print(f"Error getting synonyms: {str(e)}")
            return f"Synonyms not available for '{word}'"

    def get_explanation(self, word):
        try:
            response = self.model.generate_content(
                f"Explain the meaning and usage of the word '{word}'. "
                f"Include examples of how it's used in different contexts."
            )
            return str(response.text)
        except Exception as e:
            print(f"Error getting explanation: {str(e)}")
            return f"Explanation not available for '{word}'"

    def get_cultural_context(self, word):
        try:
            response = self.model.generate_content(
                f"Provide the cultural and historical context of the word '{word}'. "
                f"Include its origin, evolution, and significance in different cultures."
            )
            return str(response.text)
        except Exception as e:
            print(f"Error getting cultural context: {str(e)}")
            return f"Cultural context not available for '{word}'"

    def answer_question(self, question):
        try:
            response = self.model.generate_content(
                f"Answer the following question: {question}\n"
                f"Please provide a clear and concise answer."
            )
            return str(response.text)
        except Exception as e:
            print(f"Error answering question: {str(e)}")
            return "Sorry, I couldn't answer that question. Please try rephrasing it."

    def analyze_character(self, character_name):
        try:
            character_sentences = [s for s in self.sentences if character_name in s]
            if not character_sentences:
                return f"No mentions of character '{character_name}' found in the book"
                
            response = self.model.generate_content(
                f"Analyze the character {character_name} based on these sentences:\n"
                f"{' '.join(character_sentences[:10])}\n"
                f"Please provide insights about their personality, motivations, and development."
            )
            return str(response.text)
        except Exception as e:
            print(f"Error analyzing character: {str(e)}")
            return "Character analysis failed"

    def analyze_theme(self, theme):
        try:
            theme_sentences = [s for s in self.sentences if theme.lower() in s.lower()]
            if not theme_sentences:
                return f"No mentions of theme '{theme}' found in the book"
                
            response = self.model.generate_content(
                f"Analyze the theme '{theme}' based on these sentences:\n"
                f"{' '.join(theme_sentences[:10])}\n"
                f"Please provide insights about how this theme is developed in the book."
            )
            return str(response.text)
        except Exception as e:
            print(f"Error analyzing theme: {str(e)}")
            return "Theme analysis failed"