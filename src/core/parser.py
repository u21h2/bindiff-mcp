import sqlite3
import os
import logging

logger = logging.getLogger("bindiff_mcp.parser")

class BinDiffParser:
    def __init__(self, db_path):
        if not os.path.exists(db_path):
            raise FileNotFoundError(f"BinDiff DB not found: {db_path}")
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row

    
    def get_summary(self):
        """
        Returns high-level statistics about the comparison.
        """
        cursor = self.conn.cursor()
        
        # Total similarity
        try:
            cursor.execute("SELECT similarity FROM metadata")
            row = cursor.fetchone()
            similarity = row['similarity'] if row else 0.0
        except:
             similarity = 0.0

        # Matched Functions
        cursor.execute("SELECT count(*) FROM function")
        matched_funcs = cursor.fetchone()[0]
        
        cursor.execute("SELECT count(*) FROM function WHERE similarity >= 1.0")
        identical_funcs = cursor.fetchone()[0]
        
        # To get unmatched, we ideally need the total function counts of original binaries.
        # Check metadata for 'functions' column if it exists (some versions have it)
        # Otherwise we can't report unmatched count without reading the BinExport/IDB.
        # But we can report matched/identical.
        
        return {
            "overall_similarity": similarity,
            "total_matches": matched_funcs,
            "identical_functions": identical_funcs
        }

    def get_function_diffs(self, limit=50, min_similarity=0.0, max_similarity=1.0):
        """
        Returns a list of matched functions with their similarity scores.
        """
        cursor = self.conn.cursor()
        
        try:
            query = f"SELECT address1, name1, address2, name2, similarity, confidence FROM function WHERE similarity >= ? AND similarity <= ? ORDER BY similarity ASC LIMIT ?"
            cursor.execute(query, (min_similarity, max_similarity, limit))
            
            results = []
            for row in cursor.fetchall():
                res = {
                    "address1": row['address1'],
                    "name1": row['name1'],
                    "address2": row['address2'],
                    "name2": row['name2'],
                    "similarity": row['similarity'],
                    "confidence": row['confidence']
                }
                results.append(res)
                
            return results
            
        except sqlite3.OperationalError as e:
            logger.error(f"SQL Error: {e}")
            return []

    def close(self):
        self.conn.close()
