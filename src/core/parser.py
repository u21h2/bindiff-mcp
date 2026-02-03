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
        self._algorithm_cache = None

    
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
    
    def get_algorithm_names(self):
        """
        Returns a dict mapping algorithm IDs to their names from the functionalgorithm table.
        Results are cached for performance.
        """
        if self._algorithm_cache is not None:
            return self._algorithm_cache
            
        cursor = self.conn.cursor()
        algo_map = {}
        
        try:
            # Try to query the functionalgorithm table
            cursor.execute("SELECT id, name FROM functionalgorithm")
            for row in cursor.fetchall():
                algo_map[row['id']] = row['name']
        except sqlite3.OperationalError:
            # Table might not exist in older BinDiff versions
            logger.warning("functionalgorithm table not found, algorithm names unavailable")
        
        self._algorithm_cache = algo_map
        return algo_map

    def get_function_diffs(self, limit=50, min_similarity=0.0, max_similarity=1.0):
        """
        Returns a list of matched functions with their similarity scores and extended metadata.
        """
        cursor = self.conn.cursor()
        
        # Get algorithm name mapping
        algo_names = self.get_algorithm_names()
        
        try:
            # Extended query with all available columns
            query = """
                SELECT 
                    address1, name1, address2, name2, 
                    similarity, confidence, algorithm,
                    basicblocks, edges, instructions
                FROM function 
                WHERE similarity >= ? AND similarity <= ? 
                ORDER BY similarity ASC 
                LIMIT ?
            """
            cursor.execute(query, (min_similarity, max_similarity, limit))
            
            results = []
            for row in cursor.fetchall():
                algo_id = row['algorithm'] if row['algorithm'] else 0
                res = {
                    "address1": row['address1'],
                    "name1": row['name1'],
                    "address2": row['address2'],
                    "name2": row['name2'],
                    "similarity": row['similarity'],
                    "confidence": row['confidence'],
                    "algorithm": algo_names.get(algo_id, f"unknown_{algo_id}"),
                    "basicblocks": row['basicblocks'] if row['basicblocks'] else 0,
                    "edges": row['edges'] if row['edges'] else 0,
                    "instructions": row['instructions'] if row['instructions'] else 0
                }
                results.append(res)
                
            return results
            
        except sqlite3.OperationalError as e:
            logger.error(f"SQL Error: {e}")
            # Fallback to basic query if extended columns don't exist
            logger.info("Falling back to basic query without extended metadata")
            try:
                query = "SELECT address1, name1, address2, name2, similarity, confidence FROM function WHERE similarity >= ? AND similarity <= ? ORDER BY similarity ASC LIMIT ?"
                cursor.execute(query, (min_similarity, max_similarity, limit))
                
                results = []
                for row in cursor.fetchall():
                    res = {
                        "address1": row['address1'],
                        "name1": row['name1'],
                        "address2": row['address2'],
                        "name2": row['name2'],
                        "similarity": row['similarity'],
                        "confidence": row['confidence'],
                        "algorithm": "unknown",
                        "basicblocks": 0,
                        "edges": 0,
                        "instructions": 0
                    }
                    results.append(res)
                return results
            except sqlite3.OperationalError as e2:
                logger.error(f"Fallback query also failed: {e2}")
                return []

    def close(self):
        self.conn.close()

